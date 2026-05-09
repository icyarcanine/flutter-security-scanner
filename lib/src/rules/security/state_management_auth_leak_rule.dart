import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects insecure auth state handling in Flutter state management solutions.
///
/// Checks for:
/// 1. Auth tokens stored in BLoC/Riverpod/Provider state
/// 2. Auth state not cleared on logout across all state layers
/// 3. User data accessible without auth checks in state
/// 4. Auth state persisted to non-secure storage via state management
/// 5. Observable auth state that doesn't respect auth changes
///
/// This is a Flutter-specific state management security rule.
class StateManagementAuthLeakRule extends Rule {
  const StateManagementAuthLeakRule();

  @override
  String get code => 'flutter.state-management-auth-leak';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      findings.addAll(_findTokensInState(file));
      findings.addAll(_findUnprotectedUserData(file));
      findings.addAll(_findMissingAuthStateSync(file));
      findings.addAll(_findInsecureStatePersistence(file));
    }

    return findings;
  }

  /// Detects auth tokens being stored in state management classes.
  List<Finding> _findTokensInState(ScannedFile file) {
    final findings = <Finding>[];

    // Detect token fields in BLoC/Provider/Riverpod state classes.
    // Exclude event classes (e.g. LoginEvent) which are message objects,
    // not persistent state holders.
    final stateClassPattern = RegExp(
      r'(?:class\s+\w*(?:State|Bloc|Notifier|Provider|ViewModel|Controller)\w*|'
      r'@riverpod|@StateNotifierProvider|@ChangeNotifierProvider)',
      caseSensitive: false,
    );

    if (!stateClassPattern.hasMatch(file.content)) {
      return findings;
    }

    // Check for token/session fields in state.
    // Skip lines that look like constructor parameters (contain `this.`)
    // or are inside event classes.
    // Supports typed Dart declarations: `final String? jwtToken;`
    final tokenFieldPattern = RegExp(
      r'(?:String|final|var)\s+(?:\w+\??\s+)?\w*(?:token|session|jwt|credential)\w*',
      caseSensitive: false,
    );

    for (final match in tokenFieldPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      final lineText = file.lines[line - 1];
      if (isCommentLine(lineText)) continue;
      // Skip constructor parameters (e.g. `this.token`, `required this.token`)
      if (lineText.contains('this.')) continue;

      // Check if the line is within a state class, not an event class.
      final startLine = (line - 30).clamp(0, line - 1);
      final classContext = file.lines
          .sublist(startLine, line - 1)
          .join('\n')
          .toLowerCase();

      final isStateClass = classContext.contains('class') &&
          (classContext.contains('state') ||
           classContext.contains('bloc') ||
           classContext.contains('notifier') ||
           classContext.contains('provider') ||
           classContext.contains('controller'));
      final isEventClass = classContext.contains('event');

      if (isStateClass && !isEventClass) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message: 'Auth token may be stored in state management class',
          fix:
              'Store auth tokens in flutter_secure_storage, not in state '
              'management classes. State classes may be serialized, logged, '
              'or accessed by debugging tools. Use a dedicated secure storage '
              'service and keep only a non-sensitive auth status in state.',
          risk:
              'Auth tokens stored in state management can be exposed through '
              'state inspection tools, logs, or serialization. BLoC/Riverpod '
              'devtools can display full state including sensitive tokens.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  /// Detects user data accessible without auth checks.
  List<Finding> _findUnprotectedUserData(ScannedFile file) {
    final findings = <Finding>[];

    // Look for user data providers that don't check auth
    final userDataPattern = RegExp(
      r'(?:userData|currentUser|userProfile|userState|authState)',
      caseSensitive: false,
    );

    for (final match in userDataPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);

      // Check if there's an auth check nearby
      final endLine = (line + 20).clamp(0, file.lines.length);
      final surroundingContent = file.lines
          .sublist(line - 1, endLine)
          .join('\n')
          .toLowerCase();

      if (!surroundingContent.contains('isauthenticated') &&
          !surroundingContent.contains('isloggedin') &&
          !surroundingContent.contains('currentuser') &&
          !surroundingContent.contains('session') &&
          !surroundingContent.contains('auth')) {
        findings.add(Finding(
          severity: FindingSeverity.low,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message: 'User data access without auth check in state',
          fix:
              'Always check authentication status before providing user data '
              'from state. Return null or a guest state when not authenticated. '
              'Gate sensitive data behind auth checks.',
          risk:
              'Unauthenticated access to user data state can expose cached '
              'information from previous sessions, especially if state is not '
              'properly cleared on logout.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  /// Detects missing auth state synchronization.
  List<Finding> _findMissingAuthStateSync(ScannedFile file) {
    final findings = <Finding>[];

    // Look for state management classes that should sync with auth
    final stateNotifierPattern = RegExp(
      r'(?:StateNotifier|ChangeNotifier|Bloc|Cubit)',
      caseSensitive: false,
    );

    if (!stateNotifierPattern.hasMatch(file.content)) {
      return findings;
    }

    // Check for onAuthStateChange listeners
    final authListenerPattern = RegExp(
      r'onAuthStateChange|listenToAuth|authSubscription|supabase\.auth',
      caseSensitive: false,
    );

    if (!authListenerPattern.hasMatch(file.content)) {
      // Only flag when the file actually uses Supabase auth.
      // Generic auth BLoCs that handle their own lifecycle should not
      // be forced to listen to Supabase auth events.
      final hasSupabaseAuth = RegExp(
        r'supabase|Supabase|client\.auth|AuthChangeEvent',
        caseSensitive: false,
      ).hasMatch(file.content);

      // Check if the file has auth-related state
      final hasAuthState = RegExp(
        r'(?:user|auth|session|login|logout)',
        caseSensitive: false,
      ).hasMatch(file.content);

      // If the file explicitly handles logout/signout, it manages its own
      // auth lifecycle and does not need onAuthStateChange sync.
      final hasExplicitLogout = RegExp(
        r'signOut|deleteAll|logout|Logout',
        caseSensitive: false,
      ).hasMatch(file.content);

      if (hasSupabaseAuth && hasAuthState && !hasExplicitLogout) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.low,
          category: FindingCategory.security,
          code: code,
          message: 'Auth state class may not sync with Supabase auth events',
          fix:
              'Listen to Supabase auth state changes to keep state synchronized:\n\n'
              'supabase.auth.onAuthStateChange.listen((event) {\n'
              '  if (event.event == AuthChangeEvent.signedOut) {\n'
              '    state = state.copyWith(user: null, isAuthenticated: false);\n'
              '  } else if (event.event == AuthChangeEvent.signedIn) {\n'
              '    state = state.copyWith(user: event.session?.user, isAuthenticated: true);\n'
              '  }\n'
              '});',
          risk:
              'State that does not sync with auth events can become stale, '
              'showing authenticated UI after logout or losing auth context '
              'after token refresh.',
          filePath: file.relativePath,
          line: 1,
        ));
      }
    }

    return findings;
  }

  /// Detects state persistence to insecure storage.
  List<Finding> _findInsecureStatePersistence(ScannedFile file) {
    final findings = <Finding>[];

    // Look for state persistence via shared_preferences or hive
    final persistencePattern = RegExp(
      r'(?:SharedPreferences|Hive|HydratedBloc|hydrated|persist)',
      caseSensitive: false,
    );

    if (!persistencePattern.hasMatch(file.content)) {
      return findings;
    }

    // Check if auth state is being persisted
    final authPersistPattern = RegExp(
      r'(?:user|auth|session|token|credential)\s*[^\n]*(?:persist|save|write|store)',
      caseSensitive: false,
    );

    for (final match in authPersistPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      findings.add(Finding(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.medium,
        category: FindingCategory.security,
        code: code,
        message: 'Auth state persisted to potentially insecure storage',
        fix:
            'Never persist auth tokens or sensitive user data through '
            'state management persistence (HydratedBloc, SharedPreferences, '
            'Hive). Store only non-sensitive UI state. Use '
            'flutter_secure_storage for auth tokens and re-fetch user data '
            'on app restart.',
        risk:
            'State management persistence stores data in plain files that are '
            'readable by other apps. Auth tokens persisted this way are '
            'easily extracted by attackers with physical device access.',
        filePath: file.relativePath,
        line: line,
      ));
    }

    return findings;
  }
}
