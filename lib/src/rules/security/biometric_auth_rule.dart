import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects misconfigured uses of Flutter's `local_auth` package.
///
/// `local_auth` is the usual way to ask for a fingerprint/Face ID in a
/// Flutter app. The defaults are deliberately permissive (the plugin wants
/// to keep working on older phones), which means the developer has to
/// opt in to the settings that actually make biometric auth a security
/// control rather than decoration. In practice most projects ship with
/// the wrong defaults.
///
/// This rule flags:
///
/// * `authenticate(` calls that do NOT pass `biometricOnly: true`. Without
///   that flag, `local_auth` falls back to the device PIN/pattern/password,
///   which is often "1234" or whatever the user drew when they first
///   unboxed the phone. Biometric-grade auth is no longer guaranteed.
///
/// * `authenticate(` calls that do NOT pass `stickyAuth: true`. Without
///   sticky auth, the biometric prompt is torn down the instant the app
///   is backgrounded (including by an incoming call) and the caller is
///   treated as "cancelled" — very easy for an attacker to race.
///
/// * `canCheckBiometrics` used as if it were an auth call. Reading the
///   availability getter and then proceeding without calling
///   `authenticate()` is a common anti-pattern: the UI "unlocks" on the
///   presence of the sensor, not on the user ever having touched it.
///
/// * Projects that import `local_auth` but never call `authenticate()`
///   at all — a lower-confidence hint that the package is a stub or
///   dead code.
class BiometricAuthRule extends Rule {
  const BiometricAuthRule();

  @override
  String get code => 'biometric-auth';

  static final _authenticatePattern = RegExp(
    r'\.authenticate\s*\(',
  );

  static final _localAuthImport = RegExp(
    r'''import\s+['"]package:local_auth/local_auth(?:\.dart|_[a-z]+/local_auth_[a-z]+\.dart)['"]''',
  );

  static final _canCheckPattern = RegExp(
    r'\bcanCheckBiometrics\b',
  );

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.dartFiles) {
      if (!_localAuthImport.hasMatch(file.content)) continue;

      final authenticateMatches = _authenticatePattern
          .allMatches(file.content)
          .toList();

      // If local_auth is imported but no authenticate() calls exist at all,
      // the app is advertising biometric capability it never exercises.
      if (authenticateMatches.isEmpty) {
        // See whether canCheckBiometrics is the ONLY thing being used — if
        // so, it's the "read the sensor status and pretend we authed" trap.
        final canCheckOnly = _canCheckPattern.hasMatch(file.content);
        final offset = canCheckOnly
            ? _canCheckPattern.firstMatch(file.content)!.start
            : _localAuthImport.firstMatch(file.content)!.start;
        findings.add(
          Finding(
            severity: canCheckOnly
                ? FindingSeverity.medium
                : FindingSeverity.low,
            confidence: FindingConfidence.medium,
            category: FindingCategory.security,
            code: code,
            message: canCheckOnly
                ? 'canCheckBiometrics is read but authenticate() is never called'
                : 'local_auth is imported but authenticate() is never called',
            fix:
                'Call auth.authenticate(localizedReason: …, options: const '
                'AuthenticationOptions(biometricOnly: true, stickyAuth: true)) '
                'as an explicit gate on any sensitive action. Reading '
                'canCheckBiometrics only tells you whether the hardware '
                'exists — it does NOT prove the user is present.',
            risk:
                'Gating a UI on sensor availability rather than on a real '
                'authenticate() result means any attacker with physical '
                'access to the unlocked device gets straight through, '
                'because the prompt never actually fires.',
            filePath: file.relativePath,
            line: file.lineForOffset(offset),
          ),
        );
        continue;
      }

      // Per-method anti-pattern: `canCheckBiometrics` read inside a function
      // body that never actually calls `.authenticate(`. We locate the
      // enclosing `{…}` block for each reference and inspect just that
      // scope — this catches "use sensor availability as a pass/fail gate"
      // even when the file as a whole has other (legitimate) authenticate
      // calls elsewhere.
      for (final match in _canCheckPattern.allMatches(file.content)) {
        if (isOffsetCommented(file, match.start)) continue;
        final block = _enclosingBlock(file.content, match.start);
        if (block == null) continue;
        if (block.contains('.authenticate(')) continue;
        findings.add(
          Finding(
            severity: FindingSeverity.medium,
            confidence: FindingConfidence.high,
            category: FindingCategory.security,
            code: code,
            message:
                'canCheckBiometrics is used as an auth gate without calling '
                'authenticate()',
            fix:
                'canCheckBiometrics only tells you whether the device has '
                'enrolled biometrics. Pair it with a real call to '
                'auth.authenticate(localizedReason: …, options: const '
                'AuthenticationOptions(biometricOnly: true, stickyAuth: '
                'true)) before granting access.',
            risk:
                'Using canCheckBiometrics as an "authenticated" signal '
                'means any attacker with the unlocked device — or any '
                'attacker on an emulator with biometrics enrolled — sails '
                'past the check without ever touching the sensor.',
            filePath: file.relativePath,
            line: file.lineForOffset(match.start),
          ),
        );
      }

      for (final match in authenticateMatches) {
        if (isOffsetCommented(file, match.start)) continue;

        // Find the matching close paren for this authenticate( call.
        final openParen = match.end - 1;
        final closeParen = _matchParen(file.content, openParen);
        if (closeParen == -1) continue;

        final args = file.content.substring(openParen + 1, closeParen);

        // `stickyAuth: true` / `biometricOnly: true` can be inside a named
        // `AuthenticationOptions()` constructor rather than at the top
        // level — walk the full arg string either way.
        final hasBiometricOnly = RegExp(
          r'biometricOnly\s*:\s*true\b',
        ).hasMatch(args);
        final hasStickyAuth = RegExp(
          r'stickyAuth\s*:\s*true\b',
        ).hasMatch(args);

        if (!hasBiometricOnly) {
          findings.add(
            Finding(
              severity: FindingSeverity.medium,
              confidence: FindingConfidence.high,
              category: FindingCategory.security,
              code: code,
              message:
                  'local_auth.authenticate() is missing biometricOnly: true',
              fix:
                  'Pass options: const AuthenticationOptions(biometricOnly: '
                  'true, stickyAuth: true). Without biometricOnly the plugin '
                  'silently falls back to the device PIN/pattern/password, '
                  'which may be trivially guessable.',
              risk:
                  'Allowing device credential fallback downgrades the check '
                  'from "the enrolled user is present" to "whoever knows the '
                  'unlock code" — often the same 4 digits the user typed in '
                  'when they unboxed the phone.',
              filePath: file.relativePath,
              line: file.lineForOffset(match.start),
            ),
          );
        }

        if (!hasStickyAuth) {
          findings.add(
            Finding(
              severity: FindingSeverity.low,
              confidence: FindingConfidence.high,
              category: FindingCategory.security,
              code: code,
              message:
                  'local_auth.authenticate() is missing stickyAuth: true',
              fix:
                  'Add stickyAuth: true to AuthenticationOptions so an '
                  'incoming phone call or an app switch does not cancel the '
                  'biometric prompt and race the caller.',
              risk:
                  'Without stickyAuth, backgrounding the app mid-prompt '
                  'cancels the authentication silently — attackers can '
                  'force that by triggering an OS-level interruption.',
              filePath: file.relativePath,
              line: file.lineForOffset(match.start),
            ),
          );
        }
      }
    }

    return findings;
  }

  int _matchParen(String content, int openIdx) {
    var depth = 0;
    for (var i = openIdx; i < content.length; i++) {
      final ch = content[i];
      if (ch == '(') depth++;
      if (ch == ')') {
        depth--;
        if (depth == 0) return i;
      }
      if (ch == ';' && depth == 0) return -1;
    }
    return -1;
  }

  /// Returns the substring representing the innermost `{…}` block that
  /// encloses the given offset, or null when no enclosing block exists.
  ///
  /// This is a cheap "walk backward counting braces" implementation. It
  /// isn't aware of string literals or comments, but those are extremely
  /// unlikely to contain `canCheckBiometrics` so the approximation is
  /// good enough to keep the rule dependency-free.
  String? _enclosingBlock(String content, int offset) {
    var depth = 0;
    var openIdx = -1;
    for (var i = offset; i >= 0; i--) {
      final ch = content[i];
      if (ch == '}') depth++;
      if (ch == '{') {
        if (depth == 0) {
          openIdx = i;
          break;
        }
        depth--;
      }
    }
    if (openIdx == -1) return null;
    var closeDepth = 0;
    for (var i = openIdx; i < content.length; i++) {
      final ch = content[i];
      if (ch == '{') closeDepth++;
      if (ch == '}') {
        closeDepth--;
        if (closeDepth == 0) return content.substring(openIdx, i + 1);
      }
    }
    return null;
  }
}
