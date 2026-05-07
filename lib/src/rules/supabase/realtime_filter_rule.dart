import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Flags Supabase Realtime subscriptions that listen to a table without a
/// `filter:` scoping the rows to the current user.
///
/// Supabase Realtime tails Postgres logical replication and pushes every
/// change matching the subscription to every subscribed client. Row Level
/// Security is applied, but ONLY for SELECTs — and only when the project
/// has been configured with the realtime RLS helpers. Even when RLS is
/// active, a subscription without a `filter:` is still wasteful: every
/// client reads every change and then discards the ones it is not
/// authorised to see, which is a lateral information-leak hazard (timing,
/// row counts) and a large bandwidth bill.
///
/// Both the legacy `on(RealtimeListenTypes.postgresChanges, …)` API and
/// the modern `onPostgresChanges(…)` API are covered.
class SupabaseRealtimeFilterRule extends Rule {
  const SupabaseRealtimeFilterRule();

  @override
  String get code => 'supabase-realtime-filter';

  /// Matches the opening of a realtime postgres-changes subscription.
  /// Group 1 captures which API variant was used so the finding message
  /// can be precise.
  static final _subscriptionPattern = RegExp(
    r'\.(onPostgresChanges|on)\s*\(',
  );

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.supabaseCandidateDartFiles) {
      for (final match in _subscriptionPattern.allMatches(file.content)) {
        final callStart = match.end; // points at char after `(`
        final closeIndex = _findArgsClose(file.content, callStart);
        if (closeIndex == -1) continue;
        final argBody = file.content.substring(callStart, closeIndex);

        final api = match.group(1)!;
        if (api == 'on') {
          // Legacy API: .on(RealtimeListenTypes.postgresChanges, ChannelFilter(…), callback)
          // We only care about the postgres-changes variant — ignore
          // broadcast/presence which do not route through RLS.
          if (!argBody.contains('postgresChanges')) continue;
        }

        if (_hasFilter(argBody)) continue;

        final line = file.lineForOffset(match.start);
        if (isOffsetCommented(file, match.start) ||
            isCommentLine(file.lines[line - 1])) continue;

        findings.add(
          Finding(
            severity: FindingSeverity.medium,
            confidence: FindingConfidence.medium,
            category: FindingCategory.supabase,
            code: code,
            message: api == 'onPostgresChanges'
                ? 'Supabase Realtime subscription without a `filter:` scope'
                : 'Supabase Realtime subscription has no `filter:` inside its ChannelFilter',
            fix:
                'Add a `filter:` argument that scopes the subscription to the current user — e.g. `filter: \'user_id=eq.\${supabase.auth.currentUser!.id}\'` — so Realtime only streams rows the subscriber is allowed to see.',
            risk:
                'Without a scoping filter, every subscribed client receives every row change in the table. RLS may drop them at the SELECT step but by then the edge server already routed the payload. This leaks row volume, timing, and — if RLS is not watertight for Realtime — the row contents themselves.',
            filePath: file.relativePath,
            line: line,
          ),
        );
      }
    }

    return findings;
  }

  /// Returns true when [argBody] contains a `filter:` keyword argument
  /// OR a `ChannelFilter(` with a `filter:` inside its own argument list.
  static bool _hasFilter(String argBody) {
    // Fast path: modern API passes filter: directly.
    if (RegExp(r'\bfilter\s*:').hasMatch(argBody)) return true;
    return false;
  }

  /// Walks [content] starting at [start] and returns the index of the
  /// matching close `)`, treating nested parens, nested braces, and
  /// string literals (single, double, triple) as atomic. Returns -1 on
  /// truncation.
  static int _findArgsClose(String content, int start) {
    var depthParen = 1; // we start just after the opening `(`
    var depthBrace = 0;
    var i = start;
    while (i < content.length) {
      final ch = content[i];
      if (ch == '\\') {
        i += 2;
        continue;
      }
      if (ch == "'" || ch == '"') {
        // Triple quoted?
        if (i + 2 < content.length &&
            content[i + 1] == ch &&
            content[i + 2] == ch) {
          final triple = '$ch$ch$ch';
          final end = content.indexOf(triple, i + 3);
          if (end == -1) return -1;
          i = end + 3;
          continue;
        }
        // Single-line string — scan to matching close, honouring escapes.
        var j = i + 1;
        while (j < content.length) {
          final cj = content[j];
          if (cj == '\\') {
            j += 2;
            continue;
          }
          if (cj == ch) break;
          if (cj == '\n') break;
          j++;
        }
        i = j + 1;
        continue;
      }
      if (ch == '(') {
        depthParen++;
      } else if (ch == ')') {
        depthParen--;
        if (depthParen == 0 && depthBrace == 0) return i;
      } else if (ch == '{') {
        depthBrace++;
      } else if (ch == '}') {
        if (depthBrace > 0) depthBrace--;
      }
      i++;
    }
    return -1;
  }
}
