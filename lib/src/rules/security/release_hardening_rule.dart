import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';

/// Detects Android release builds that ship with insufficient hardening.
///
/// Flutter's default `android/app/build.gradle` leaves several knobs in the
/// "easy" position because that's what works out of the box. For a release
/// build those defaults are wrong:
///
/// * `minifyEnabled false` on the release build type — R8 is disabled, so
///   all Java/Kotlin class names are readable in the final APK/AAB and
///   Flutter's native engine symbols are not stripped.
/// * `shrinkResources false` — unused resources ship, growing attack
///   surface for reverse engineering.
/// * `debuggable true` in the release type — lets a debugger attach to the
///   released binary.
/// * Release signed with `signingConfigs.debug` — the public Android debug
///   key. Google Play rejects this but an internal distribution might not.
///
/// It also walks CI / build scripts (GitHub Actions, Fastlane, shell
/// invocations found inside YAML files) and flags `flutter build apk` /
/// `flutter build appbundle` / `flutter build ipa` commands that do not
/// pass `--obfuscate` and `--split-debug-info`. Dart code in an unobfuscated
/// release APK is fully readable after `apktool` — secrets, API endpoints,
/// routing logic, everything. The `--obfuscate` flag is the single biggest
/// thing a Flutter developer can do to make reverse engineering expensive,
/// and almost nobody turns it on.
///
/// Severity is MEDIUM for build.gradle misconfig (deterministic) and LOW
/// for script-based CLI checks (heuristic, there may be a wrapper script).
class ReleaseHardeningRule extends Rule {
  const ReleaseHardeningRule();

  @override
  String get code => 'release-hardening';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.files) {
      final isAppGradle =
          (file.name == 'build.gradle' || file.name == 'build.gradle.kts') &&
              file.relativePath.contains('android/app');
      if (isAppGradle) {
        findings.addAll(_checkAppGradle(file));
      }

      if (file.extension == '.yml' || file.extension == '.yaml') {
        findings.addAll(_checkBuildScriptYaml(file));
      }
    }

    return findings;
  }

  // ---------------------------------------------------------------------------
  // android/app/build.gradle(.kts)
  // ---------------------------------------------------------------------------

  List<Finding> _checkAppGradle(ScannedFile file) {
    final findings = <Finding>[];
    final content = file.content;

    final releaseBlock = _extractBuildTypeBlock(content, 'release');
    if (releaseBlock == null) return findings;

    final blockStart = releaseBlock.start;
    final block = releaseBlock.body;

    void add({
      required FindingSeverity severity,
      required FindingConfidence confidence,
      required String message,
      required String fix,
      required String risk,
      int? offsetHint,
    }) {
      findings.add(
        Finding(
          severity: severity,
          confidence: confidence,
          category: FindingCategory.security,
          code: code,
          message: message,
          fix: fix,
          risk: risk,
          filePath: file.relativePath,
          line: file.lineForOffset(offsetHint ?? blockStart),
        ),
      );
    }

    // minifyEnabled: explicit false OR missing entirely.
    final minifyExplicitFalse = RegExp(
      r'minifyEnabled\s*=?\s*false\b',
    ).firstMatch(block);
    final minifyExplicitTrue = RegExp(
      r'minifyEnabled\s*=?\s*true\b',
    ).firstMatch(block);
    if (minifyExplicitFalse != null) {
      add(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.high,
        message:
            'Release build disables code shrinking (minifyEnabled = false)',
        fix:
            'Set minifyEnabled = true on the release buildType and provide '
            'proguardFiles getDefaultProguardFile("proguard-android-optimize.txt"), '
            '"proguard-rules.pro" so R8 can shrink and obfuscate Java/Kotlin '
            'bytecode.',
        risk:
            'Without R8/ProGuard shrinking, every Android/Java class name, '
            'method signature, and string constant is readable in the '
            'published APK — a huge head start for anyone reverse '
            'engineering the app.',
        offsetHint: blockStart + minifyExplicitFalse.start,
      );
    } else if (minifyExplicitTrue == null) {
      add(
        severity: FindingSeverity.low,
        confidence: FindingConfidence.medium,
        message:
            'Release build type does not declare minifyEnabled — R8 is probably off',
        fix:
            'Add `minifyEnabled = true` and proguardFiles in the release '
            'buildType. Flutter\'s default template omits it, which means '
            'R8 stays off unless you turn it on explicitly.',
        risk:
            'Unminified release builds ship every Java/Kotlin class name '
            'and resource to the user, lowering the cost of reverse '
            'engineering and exposing internal naming.',
      );
    }

    // shrinkResources false (only meaningful if minify is actually on).
    final shrinkFalse = RegExp(
      r'shrinkResources\s*=?\s*false\b',
    ).firstMatch(block);
    if (shrinkFalse != null && minifyExplicitTrue != null) {
      add(
        severity: FindingSeverity.low,
        confidence: FindingConfidence.high,
        message:
            'Release build keeps unused resources (shrinkResources = false)',
        fix:
            'Set shrinkResources = true on the release buildType so R8 can '
            'strip unused drawables, strings, and layouts.',
        risk:
            'Unused resources grow APK size and give reverse engineers '
            'additional artifacts to pivot off (old drawable names, '
            'leftover string tables).',
        offsetHint: blockStart + shrinkFalse.start,
      );
    }

    // debuggable true on the release type.
    final debuggableTrue = RegExp(
      r'debuggable\s*=?\s*true\b',
    ).firstMatch(block);
    if (debuggableTrue != null) {
      add(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.high,
        message: 'Release build type is marked debuggable = true',
        fix:
            'Remove `debuggable true` from the release buildType. Debug '
            'builds belong in the debug buildType — never ship a release '
            'APK that accepts a debugger attach.',
        risk:
            'A debuggable release lets any attacker with the APK attach a '
            'Java debugger, inspect memory, and bypass client-side '
            'security checks.',
        offsetHint: blockStart + debuggableTrue.start,
      );
    }

    // Release signed with the default Android debug key.
    final debugSigning = RegExp(
      r'signingConfig\s+signingConfigs\.debug\b|signingConfig\s*=\s*signingConfigs\.getByName\("debug"\)',
    ).firstMatch(block);
    if (debugSigning != null) {
      add(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.high,
        message:
            'Release build is signed with the Android debug keystore '
            '(signingConfigs.debug)',
        fix:
            'Create a dedicated release signingConfig backed by a keystore '
            'stored out of repo (local.properties or CI secret) and '
            'reference it from the release buildType.',
        risk:
            'The Android debug signing key is public and shared across all '
            'machines. An APK signed with it cannot be updated through the '
            'Play Store and has no proof of origin — perfect for impostor '
            'side-loaded distribution.',
        offsetHint: blockStart + debugSigning.start,
      );
    }

    return findings;
  }

  _BuildTypeBlock? _extractBuildTypeBlock(String content, String name) {
    // Find `name {` inside a `buildTypes { ... }` region. We first locate
    // buildTypes to avoid matching a `release` identifier in an unrelated
    // part of the file.
    final buildTypesIdx = content.indexOf('buildTypes');
    if (buildTypesIdx == -1) return null;

    // From buildTypes, find the opening brace and its matching close.
    final openBrace = content.indexOf('{', buildTypesIdx);
    if (openBrace == -1) return null;
    final buildTypesClose = _matchBrace(content, openBrace);
    if (buildTypesClose == -1) return null;

    // Scan for the named build type (e.g. `release {` or `getByName("release") {`).
    final buildTypesBody = content.substring(openBrace + 1, buildTypesClose);
    final namedMatch = RegExp(
      '(?:^|\\s)$name\\s*\\{|getByName\\s*\\(\\s*"$name"\\s*\\)\\s*\\{|create\\s*\\(\\s*"$name"\\s*\\)\\s*\\{',
    ).firstMatch(buildTypesBody);
    if (namedMatch == null) return null;

    // Resolve absolute offset and find the matching close brace.
    final bodyOffset = openBrace + 1 + namedMatch.end - 1; // position of `{`
    final bodyClose = _matchBrace(content, bodyOffset);
    if (bodyClose == -1) return null;

    return _BuildTypeBlock(
      start: openBrace + 1 + namedMatch.start,
      body: content.substring(bodyOffset + 1, bodyClose),
    );
  }

  int _matchBrace(String content, int openIdx) {
    if (openIdx >= content.length || content[openIdx] != '{') return -1;
    var depth = 0;
    for (var i = openIdx; i < content.length; i++) {
      final ch = content[i];
      if (ch == '{') depth++;
      if (ch == '}') {
        depth--;
        if (depth == 0) return i;
      }
    }
    return -1;
  }

  // ---------------------------------------------------------------------------
  // GitHub Actions / Fastlane / shell-in-yaml
  // ---------------------------------------------------------------------------

  /// Any `flutter build <apk|appbundle|ipa>` invocation embedded in a YAML
  /// script. Captures the full command up to the end of the line so we can
  /// inspect it for `--obfuscate`.
  static final _flutterBuildPattern = RegExp(
    r'flutter\s+build\s+(?:apk|appbundle|aab|ipa)\b[^\n\r]*',
    caseSensitive: false,
  );

  List<Finding> _checkBuildScriptYaml(ScannedFile file) {
    final findings = <Finding>[];

    for (final match in _flutterBuildPattern.allMatches(file.content)) {
      final command = match.group(0)!;
      final lower = command.toLowerCase();
      if (lower.contains('--debug')) continue; // explicit debug build
      if (lower.contains('--profile')) continue; // profile build, ok
      if (lower.contains('--obfuscate')) continue; // already hardened

      findings.add(
        Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.medium,
          category: FindingCategory.security,
          code: code,
          message:
              'Flutter build command in ${file.name} ships Dart code without obfuscation',
          fix:
              'Pass --obfuscate --split-debug-info=<outdir> to `flutter build`. '
              'Without these flags the Dart AOT snapshot inside the APK/AAB '
              'retains class and function names, making the entire Dart '
              'codebase readable via `ipatool`/`apktool`.',
          risk:
              'Unobfuscated Dart code in a release build exposes business '
              'logic, secret endpoints, and routing details to any attacker '
              'with the APK. Obfuscation + split-debug-info is free and '
              'the biggest single reverse-engineering obstacle available.',
          filePath: file.relativePath,
          line: file.lineForOffset(match.start),
        ),
      );
    }

    return findings;
  }
}

class _BuildTypeBlock {
  const _BuildTypeBlock({required this.start, required this.body});
  final int start;
  final String body;
}
