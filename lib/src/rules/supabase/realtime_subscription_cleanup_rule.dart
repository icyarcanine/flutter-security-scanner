import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../models/scanned_file.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Detects Supabase Realtime subscriptions that are never cancelled,
/// leading to memory leaks and stale listeners.
///
/// Checks for:
/// 1. subscribe() without a matching unsubscribe() or cancel()
/// 2. StreamSubscription stored but never cancelled in dispose()
/// 3. onAuthStateChange subscriptions without cleanup
/// 4. Realtime channels left open when widget/page closes
///
/// This is a Flutter-specific resource management rule.
class RealtimeSubscriptionCleanupRule extends Rule {
  const RealtimeSubscriptionCleanupRule();

  @override
  String get code => 'supabase.realtime-subscription-cleanup';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.appDartFiles) {
      findings.addAll(_findUncancelledSubscriptions(file));
      findings.addAll(_findMissingDisposeCleanup(file));
      findings.addAll(_findAuthListenersWithoutCleanup(file));
    }

    return findings;
  }

  /// Detects subscribe() calls without unsubscribe() in the same file.
  /// Only flags Supabase-specific subscriptions within widget/state classes,
  /// not global app-lifetime listeners in main() or top-level functions.
  List<Finding> _findUncancelledSubscriptions(ScannedFile file) {
    final findings = <Finding>[];

    // Only scan files that look like they contain Supabase realtime usage.
    final hasRealtimeUsage = RegExp(
      r'supabase|channel|realtime|postgresChanges|stream\(',
      caseSensitive: false,
    ).hasMatch(file.content);
    if (!hasRealtimeUsage) return findings;

    // Skip top-level main() files — global app-lifetime subscriptions there
    // are typically intentional and managed by the app lifecycle.
    final isMainFile = file.name.toLowerCase() == 'main.dart';
    final hasMainFunction = RegExp(r'\bmain\s*\(').hasMatch(file.content);
    if (isMainFile && hasMainFunction) return findings;

    final subscribePattern = RegExp(
      r'\.(subscribe|listen)\s*\(',
      caseSensitive: false,
    );

    final unsubscribePattern = RegExp(
      r'\.(unsubscribe|cancel)\s*\(',
      caseSensitive: false,
    );

    final hasUnsubscribe = unsubscribePattern.hasMatch(file.content);

    for (final match in subscribePattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      // Only flag if the subscribe is near Supabase/realtime context
      final contextStart = (line - 5).clamp(0, line - 1);
      final contextEnd = (line + 3).clamp(0, file.lines.length);
      final nearbyContext = file.lines
          .sublist(contextStart, contextEnd)
          .join('\n')
          .toLowerCase();
      if (!nearbyContext.contains('supabase') &&
          !nearbyContext.contains('channel') &&
          !nearbyContext.contains('realtime') &&
          !nearbyContext.contains('stream')) {
        continue;
      }

      // If there's no unsubscribe at all in the file, flag every subscribe
      if (!hasUnsubscribe) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.low,
          category: FindingCategory.supabase,
          code: code,
          message: 'Realtime subscription may not be cancelled, causing memory leaks',
          fix:
              'Store the subscription and cancel it when the widget is disposed '
              'or the screen is popped:\n\n'
              'StreamSubscription? _subscription;\n\n'
              '@override\n'
              'void initState() {\n'
              '  super.initState();\n'
              '  _subscription = supabase\n'
              '      .from("messages")\n'
              '      .stream(primaryKey: ["id"])\n'
              '      .listen(handleMessage);\n'
              '}\n\n'
              '@override\n'
              'void dispose() {\n'
              '  _subscription?.cancel();\n'
              '  super.dispose();\n'
              '}',
          risk:
              'Uncancelled subscriptions accumulate in memory and continue '
              'receiving events after the widget is disposed, causing memory '
              'leaks, unexpected UI updates, and wasted bandwidth.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  /// Detects classes with subscription fields but no cancel in dispose().
  List<Finding> _findMissingDisposeCleanup(ScannedFile file) {
    final findings = <Finding>[];

    // Look for StreamSubscription or RealtimeChannel fields
    final subscriptionFieldPattern = RegExp(
      r'(?:StreamSubscription|RealtimeChannel|RealtimeSubscription)\s*(?:\?)?\s+(?:\w+)',
      caseSensitive: false,
    );

    final disposePattern = RegExp(
      r'void\s+dispose\s*\(\s*\)',
      caseSensitive: false,
    );

    final cancelInDisposePattern = RegExp(
      r'\.cancel\s*\(\s*\)|\.unsubscribe\s*\(\s*\)',
      caseSensitive: false,
    );

    final hasDispose = disposePattern.hasMatch(file.content);
    final hasCancelInDispose = cancelInDisposePattern.hasMatch(file.content);

    for (final match in subscriptionFieldPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      if (!hasDispose || !hasCancelInDispose) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.medium,
          category: FindingCategory.supabase,
          code: code,
          message: 'Subscription field declared but may not be cancelled in dispose()',
          fix:
              'Add a dispose() method that cancels all subscriptions:\n\n'
              '@override\n'
              'void dispose() {\n'
              '  _subscription?.cancel();\n'
              '  _channel?.unsubscribe();\n'
              '  super.dispose();\n'
              '}',
          risk:
              'StatefulWidget subclasses that store subscriptions without '
              'cancelling them in dispose() leak memory and may crash when '
              'setState() is called after the widget is unmounted.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }

  /// Detects onAuthStateChange listeners without cleanup.
  List<Finding> _findAuthListenersWithoutCleanup(ScannedFile file) {
    final findings = <Finding>[];

    final authListenPattern = RegExp(
      r'(?:supabase|client)\.auth\.onAuthStateChange',
      caseSensitive: false,
    );

    final cancelPattern = RegExp(
      r'\.cancel\s*\(\s*\)',
      caseSensitive: false,
    );

    final hasCancel = cancelPattern.hasMatch(file.content);

    for (final match in authListenPattern.allMatches(file.content)) {
      final line = file.lineForOffset(match.start);
      if (isCommentLine(file.lines[line - 1])) continue;

      if (!hasCancel) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.medium,
          category: FindingCategory.supabase,
          code: code,
          message: 'Auth state listener may not be cancelled',
          fix:
              'Store the auth state subscription and cancel it when no longer '
              'needed, typically in dispose() or when the user logs out:\n\n'
              'late final StreamSubscription<AuthState> _authSub;\n\n'
              '@override\n'
              'void initState() {\n'
              '  super.initState();\n'
              '  _authSub = supabase.auth.onAuthStateChange.listen((event) {\n'
              '    // handle auth changes\n'
              '  });\n'
              '}\n\n'
              '@override\n'
              'void dispose() {\n'
              '  _authSub.cancel();\n'
              '  super.dispose();\n'
              '}',
          risk:
              'Auth state listeners that are never cancelled continue firing '
              'after the owning widget is disposed, causing memory leaks and '
              'potential null-reference crashes.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    return findings;
  }
}
