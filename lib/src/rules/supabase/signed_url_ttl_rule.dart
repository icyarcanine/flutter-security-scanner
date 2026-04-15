import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

/// Flags Supabase Storage `createSignedUrl` / `createSignedUrls` /
/// `createSignedUploadUrl` calls that hand out a signed URL with a TTL
/// longer than the recommended ceiling.
///
/// A signed URL is a bearer credential. Once issued, it is valid from
/// any client — shared over chat, cached in logs, or pulled out of a
/// disk screenshot — until the TTL expires. Long TTLs are the storage
/// equivalent of publishing a long-lived access token: a stolen link
/// unlocks the asset for hours, days, or years depending on how the
/// developer rounded up.
///
/// Thresholds:
/// * `> 3600` seconds (1 h)   → medium / medium
/// * `> 86400` seconds (24 h) → high / medium
///
/// Non-numeric TTLs (variables, `const kTtl`, arithmetic expressions)
/// are reported at low confidence so the developer at least eyeballs
/// the call site.
class SupabaseSignedUrlTtlRule extends Rule {
  const SupabaseSignedUrlTtlRule();

  @override
  String get code => 'supabase-signed-url-ttl';

  static const int _warnThreshold = 3600; // 1 hour
  static const int _highThreshold = 86400; // 1 day

  static final _callPattern = RegExp(
    r'\.(createSignedUrl|createSignedUrls|createSignedUploadUrl)\s*\(',
  );

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final file in context.supabaseCandidateDartFiles) {
      for (final match in _callPattern.allMatches(file.content)) {
        final method = match.group(1)!;
        final callOpen = match.end;
        final closeIndex = _findParenClose(file.content, callOpen);
        if (closeIndex == -1) continue;
        final argBody = file.content.substring(callOpen, closeIndex);
        final args = _splitTopLevelArgs(argBody);

        // `createSignedUrls` (plural) takes `(paths, expiresIn)` and the
        // TTL is still the second argument. `createSignedUploadUrl` only
        // takes the path — the TTL is fixed at 2 hours by the server —
        // so we skip it here.
        if (method == 'createSignedUploadUrl') continue;
        if (args.length < 2) continue;

        final ttlExpr = args[1].trim();
        final ttlSeconds = _parseTtl(ttlExpr);

        final line = file.lineForOffset(match.start);
        if (isOffsetCommented(file, match.start) ||
            isCommentLine(file.lines[line - 1])) continue;

        if (ttlSeconds == null) {
          findings.add(
            Finding(
              severity: FindingSeverity.low,
              confidence: FindingConfidence.low,
              category: FindingCategory.supabase,
              code: code,
              message:
                  '`$method` TTL `$ttlExpr` is not a literal — verify the value is short and bounded',
              fix:
                  'Hardcode a short numeric TTL (ideally ≤ 3600 seconds) or resolve the variable to a named constant you can audit. Signed URLs are bearer credentials — the TTL is the entire security model.',
              risk:
                  'Dynamic TTLs expand silently. A shared constant tuned once to 24 h quietly becomes the effective lifetime of every leaked link across the codebase.',
              filePath: file.relativePath,
              line: line,
            ),
          );
          continue;
        }

        if (ttlSeconds > _highThreshold) {
          findings.add(
            Finding(
              severity: FindingSeverity.high,
              confidence: FindingConfidence.medium,
              category: FindingCategory.supabase,
              code: code,
              message:
                  '`$method` TTL is ${_humanise(ttlSeconds)} — signed URLs should expire in ≤ 1 hour for sensitive assets',
              fix:
                  'Lower the TTL to 3600 seconds or less for user-scoped downloads. If you need a longer-lived URL (background export, webhook handoff), issue it from a backend function that can audit the recipient.',
              risk:
                  'A signed URL is a bearer credential. A multi-day TTL means one leaked link — in a chat log, a screenshot, a proxy cache — grants full access for the entire window with no way to revoke.',
              filePath: file.relativePath,
              line: line,
            ),
          );
        } else if (ttlSeconds > _warnThreshold) {
          findings.add(
            Finding(
              severity: FindingSeverity.medium,
              confidence: FindingConfidence.medium,
              category: FindingCategory.supabase,
              code: code,
              message:
                  '`$method` TTL is ${_humanise(ttlSeconds)} — signed URLs should expire quickly',
              fix:
                  'Reduce the TTL to 3600 seconds or less for most user-facing downloads. If the client needs more time, refresh the signed URL close to download time rather than pre-issuing a long-lived one.',
              risk:
                  'Longer-lived signed URLs extend the window during which a leaked link (chat, logs, proxies, screenshots) can exfiltrate the asset.',
              filePath: file.relativePath,
              line: line,
            ),
          );
        }
      }
    }

    return findings;
  }

  /// Parses an explicit TTL literal. Accepts plain integers, underscores
  /// (`3_600`), and simple Duration constants (`Duration(hours: 2).inSeconds`).
  /// Anything more complex returns null so the caller drops to the
  /// low-confidence "dynamic TTL" branch.
  static int? _parseTtl(String expr) {
    final cleaned = expr.replaceAll('_', '').trim();
    final intMatch = RegExp(r'^\d+$').firstMatch(cleaned);
    if (intMatch != null) {
      return int.tryParse(intMatch.group(0)!);
    }

    // Duration literal with a single keyword: Duration(hours: 6), Duration(days: 1)…
    final durationPattern = RegExp(
      r'^Duration\s*\(\s*(seconds|minutes|hours|days)\s*:\s*(\d+)\s*\)(?:\.inSeconds)?$',
    );
    final durationMatch = durationPattern.firstMatch(cleaned);
    if (durationMatch != null) {
      final unit = durationMatch.group(1)!;
      final value = int.parse(durationMatch.group(2)!);
      switch (unit) {
        case 'seconds':
          return value;
        case 'minutes':
          return value * 60;
        case 'hours':
          return value * 3600;
        case 'days':
          return value * 86400;
      }
    }

    return null;
  }

  static String _humanise(int seconds) {
    if (seconds >= 86400) {
      final days = seconds / 86400;
      return '${_format(days)} day${days == 1 ? '' : 's'}';
    }
    if (seconds >= 3600) {
      final hours = seconds / 3600;
      return '${_format(hours)} hour${hours == 1 ? '' : 's'}';
    }
    if (seconds >= 60) {
      final minutes = seconds / 60;
      return '${_format(minutes)} minute${minutes == 1 ? '' : 's'}';
    }
    return '$seconds second${seconds == 1 ? '' : 's'}';
  }

  static String _format(double value) {
    if (value == value.roundToDouble()) return value.toStringAsFixed(0);
    return value.toStringAsFixed(1);
  }

  /// String-aware paren walker — starts just after `(` and returns the
  /// matching `)` index.
  static int _findParenClose(String content, int start) {
    var depth = 1;
    var i = start;
    while (i < content.length) {
      final ch = content[i];
      if (ch == '\\') {
        i += 2;
        continue;
      }
      if (ch == "'" || ch == '"') {
        if (i + 2 < content.length &&
            content[i + 1] == ch &&
            content[i + 2] == ch) {
          final triple = '$ch$ch$ch';
          final end = content.indexOf(triple, i + 3);
          if (end == -1) return -1;
          i = end + 3;
          continue;
        }
        var j = i + 1;
        while (j < content.length) {
          final cj = content[j];
          if (cj == '\\') {
            j += 2;
            continue;
          }
          if (cj == ch || cj == '\n') break;
          j++;
        }
        i = j + 1;
        continue;
      }
      if (ch == '(') {
        depth++;
      } else if (ch == ')') {
        depth--;
        if (depth == 0) return i;
      }
      i++;
    }
    return -1;
  }

  /// Splits the argument list at top-level commas, ignoring commas that
  /// appear inside nested parens, brackets, braces, or strings.
  static List<String> _splitTopLevelArgs(String body) {
    final result = <String>[];
    var depth = 0;
    var start = 0;
    var i = 0;
    while (i < body.length) {
      final ch = body[i];
      if (ch == '\\') {
        i += 2;
        continue;
      }
      if (ch == "'" || ch == '"') {
        if (i + 2 < body.length && body[i + 1] == ch && body[i + 2] == ch) {
          final triple = '$ch$ch$ch';
          final end = body.indexOf(triple, i + 3);
          if (end == -1) return [body];
          i = end + 3;
          continue;
        }
        var j = i + 1;
        while (j < body.length) {
          final cj = body[j];
          if (cj == '\\') {
            j += 2;
            continue;
          }
          if (cj == ch || cj == '\n') break;
          j++;
        }
        i = j + 1;
        continue;
      }
      if (ch == '(' || ch == '[' || ch == '{') {
        depth++;
      } else if (ch == ')' || ch == ']' || ch == '}') {
        depth--;
      } else if (ch == ',' && depth == 0) {
        result.add(body.substring(start, i));
        start = i + 1;
      }
      i++;
    }
    if (start < body.length) {
      result.add(body.substring(start));
    }
    return result;
  }
}
