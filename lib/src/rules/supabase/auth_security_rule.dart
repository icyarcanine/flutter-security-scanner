import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects insecure Supabase auth patterns in Flutter code.
///
/// Checks for:
/// 1. Missing redirectTo in OAuth flows
/// 2. Missing nonce in signInWithIdToken
/// 3. Storing auth tokens in insecure storage (SharedPreferences, plain variables)
/// 4. signOut without clearing local state
/// 5. Using session without expiration check
/// 6. signInWithPassword without rate limiting
///
/// This is a Flutter+Supabase integration-specific rule.
class SupabaseAuthSecurityRule extends Rule {
  const SupabaseAuthSecurityRule();

  @override
  String get code => 'supabase.auth-security';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      findings.addAll(_findOAuthMissingRedirect(file));
      findings.addAll(_findIdTokenMissingNonce(file));
      findings.addAll(_findInsecureTokenStorage(file));
      findings.addAll(_findIncompleteSignOut(file));
      findings.addAll(_findUnvalidatedSession(file));
      findings.addAll(_findPasswordAuthWithoutRateLimit(file));
    }

    return findings;
  }

  /// Detects signInWithOAuth calls without redirectTo parameter.
  List<Finding> _findOAuthMissingRedirect(ScannedFile file) {
    final findings = <Finding>[];
    final pattern = RegExp(
      r'signInWithOAuth\s*\(\s*OAuthProvider\.\w+\s*\)',
      caseSensitive: false,
    );

    for (final match in pattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      findings.add(Finding(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.medium,
        category: FindingCategory.security,
        code: code,
        message: 'OAuth sign-in missing redirectTo parameter',
        fix:
            'Always specify a redirectTo URL that matches your registered '
            'OAuth callback URLs. Example: redirectTo: "myapp://callback"',
        risk:
            'Without redirect URL validation, the OAuth flow may redirect to '
            'an attacker-controlled URL, leading to token theft.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  /// Detects signInWithIdToken calls without nonce parameter.
  List<Finding> _findIdTokenMissingNonce(ScannedFile file) {
    final findings = <Finding>[];
    // Match signInWithIdToken calls that don't have a nonce parameter
    final pattern = RegExp(
      r'signInWithIdToken\s*\([^)]*\)',
      caseSensitive: false,
    );

    for (final match in pattern.allMatches(file.content)) {
      final callContent = match.group(0)!;
      // Skip if nonce is present
      if (callContent.contains('nonce')) continue;

      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      findings.add(Finding(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.medium,
        category: FindingCategory.security,
        code: code,
        message: 'ID token sign-in missing nonce validation',
        fix:
            'Always include a cryptographically random nonce when calling '
            'signInWithIdToken. Validate the nonce matches between the auth '
            'request and the token response.',
        risk:
            'Without nonce validation, the ID token could be replayed by an '
            'attacker in a token replay attack.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  /// Detects auth tokens stored in insecure storage.
  List<Finding> _findInsecureTokenStorage(ScannedFile file) {
    final findings = <Finding>[];

    // SharedPreferences with token/session/auth key - look for the method call
    final prefsPattern = RegExp(
      r'SharedPreferences.*\.(?:setString|write)\s*\([^)]*(?:token|session|auth)',
      caseSensitive: false,
    );

    for (final match in prefsPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      findings.add(Finding(
        severity: FindingSeverity.high,
        confidence: FindingConfidence.high,
        category: FindingCategory.security,
        code: code,
        message: 'Auth token stored in insecure SharedPreferences',
        fix:
            'Use flutter_secure_storage (Keychain on iOS, EncryptedSharedPreferences '
            'on Android) for all auth tokens and session data.',
        risk:
            'SharedPreferences is not encrypted on Android. Other apps with '
            'root access can read these values.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    // Plain variable assignment from Supabase session/token
    final varPattern = RegExp(
      r'(?:String|var|final|const)\s+\w*(?:token|session|auth)\w*\s*=\s*(?:Supabase|client\.auth)',
      caseSensitive: false,
    );

    for (final match in varPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      findings.add(Finding(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.medium,
        category: FindingCategory.security,
        code: code,
        message: 'Auth token stored in plain variable',
        fix:
            'Store auth tokens using flutter_secure_storage or encrypted '
            'SharedPreferences. Never keep tokens in plain variables.',
        risk:
            'Authentication tokens stored in plain variables are accessible '
            'to other apps via memory inspection.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }

  /// Detects signOut that doesn't clear local state.
  List<Finding> _findIncompleteSignOut(ScannedFile file) {
    final findings = <Finding>[];

    // Find signOut calls and check if the surrounding 10 lines have state clearing
    final signOutPattern = RegExp(
      r'signOut\s*\(\s*\)',
      caseSensitive: false,
    );

    for (final match in signOutPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      // Check next 15 lines for state clearing
      final endLine = (line + 15).clamp(0, file.lines.length);
      final surroundingContent = file.lines
          .sublist(line - 1, endLine)
          .join('\n')
          .toLowerCase();

      // If no clearing of storage, state, or user data
      if (!surroundingContent.contains('deleteall') &&
          !surroundingContent.contains('delete(') &&
          !surroundingContent.contains('clear()') &&
          !surroundingContent.contains('setstate') &&
          !surroundingContent.contains('remove(')) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message: 'signOut may not clear all local auth state',
          fix:
              'After calling signOut(), explicitly clear all local auth state: '
              'delete tokens from secure storage, clear user data from memory, '
              'and reset auth-related state in your state management solution.',
          risk:
              'Cached tokens, user data, or session info may remain insecurely '
              'stored after logout, allowing unauthorized access.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  /// Detects getSession without expiration check.
  List<Finding> _findUnvalidatedSession(ScannedFile file) {
    final findings = <Finding>[];

    final sessionPattern = RegExp(
      r'(?:final|var)\s+\w*\s*=\s*(?:await\s+)?(?:Supabase|client\.auth)\.getSession\(\)',
      caseSensitive: false,
    );

    for (final match in sessionPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      // Check next 20 lines for expiration validation
      final endLine = (line + 20).clamp(0, file.lines.length);
      final surroundingContent = file.lines
          .sublist(line - 1, endLine)
          .join('\n')
          .toLowerCase();

      if (!surroundingContent.contains('isexpired') &&
          !surroundingContent.contains('expiresat') &&
          !surroundingContent.contains('refreshsession')) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message: 'Session used without expiration check',
          fix:
              'Always check session expiration before using tokens. Use '
              'supabase.auth.onAuthStateChange to listen for token refresh '
              'events, and call refreshSession when tokens are near expiration.',
          risk:
              'Using an expired session can lead to unexpected auth failures '
              'or security vulnerabilities if the expired token is sent to the server.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  /// Detects signInWithPassword without rate limiting.
  List<Finding> _findPasswordAuthWithoutRateLimit(ScannedFile file) {
    final findings = <Finding>[];

    final passwordPattern = RegExp(
      r'signInWithPassword\s*\(',
      caseSensitive: false,
    );

    for (final match in passwordPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      // Check previous 20 lines for rate limiting
      final startLine = (line - 20).clamp(0, line - 1);
      final surroundingContent = file.lines
          .sublist(startLine, line - 1)
          .join('\n')
          .toLowerCase();

      if (!surroundingContent.contains('delay') &&
          !surroundingContent.contains('throttle') &&
          !surroundingContent.contains('ratelimit') &&
          !surroundingContent.contains('cooldown') &&
          !surroundingContent.contains('debounce')) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message: 'Password sign-in lacks brute-force protection',
          fix:
              'Implement client-side rate limiting (e.g., exponential backoff) '
              'before calling signInWithPassword. Consider adding CAPTCHA for '
              'repeated failed attempts.',
          risk:
              'Without client-side rate limiting, attackers can rapidly attempt '
              'password guesses, increasing load on your server and potentially '
              'breaching accounts with weak passwords.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }
}
