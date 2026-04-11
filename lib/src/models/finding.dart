enum FindingSeverity { high, medium, low }

enum FindingCategory { security, config, supabase, suggestion }

/// How confident the scanner is that this finding is a real issue.
///
/// * [high] — triggered by a deterministic, unambiguous pattern (e.g. a JWT
///   string literal assigned to `anonKey`).
/// * [medium] — triggered by a reliable heuristic with low false-positive
///   potential (e.g. a table query without a visible ownership filter).
/// * [low] — triggered by a weak signal that requires human judgment (e.g.
///   only informal/markdown RLS evidence found in the project).
enum FindingConfidence { high, medium, low }

extension FindingSeverityLabel on FindingSeverity {
  String get label => switch (this) {
    FindingSeverity.high => 'HIGH',
    FindingSeverity.medium => 'MEDIUM',
    FindingSeverity.low => 'LOW',
  };

  int get sortOrder => switch (this) {
    FindingSeverity.high => 0,
    FindingSeverity.medium => 1,
    FindingSeverity.low => 2,
  };
}

extension FindingCategoryLabel on FindingCategory {
  String get label => switch (this) {
    FindingCategory.security => 'SECURITY',
    FindingCategory.config => 'CONFIG',
    FindingCategory.supabase => 'SUPABASE',
    FindingCategory.suggestion => 'SUGGESTION',
  };
}

extension FindingConfidenceLabel on FindingConfidence {
  String get label => switch (this) {
    FindingConfidence.high => 'HIGH',
    FindingConfidence.medium => 'MEDIUM',
    FindingConfidence.low => 'LOW',
  };
}

class Finding {
  const Finding({
    required this.category,
    required this.code,
    required this.message,
    required this.fix,
    this.risk,
    this.severity,
    this.confidence,
    this.filePath,
    this.line,
  });

  final FindingSeverity? severity;
  final FindingCategory category;
  final FindingConfidence? confidence;
  final String code;
  final String message;
  final String fix;

  /// One-line explanation of what goes wrong if this issue is ignored.
  /// Shown in terminal output when present.
  final String? risk;

  final String? filePath;
  final int? line;

  bool get isSuggestion => category == FindingCategory.suggestion;

  String get locationLabel {
    if (filePath == null) {
      return '';
    }
    if (line == null) {
      return ' in $filePath';
    }
    return ' in $filePath:$line';
  }

  String toConsoleBlock() {
    // Build the bracket prefix.
    final buffer = StringBuffer();
    if (isSuggestion) {
      buffer.write('[${category.label}]');
    } else {
      buffer.write('[${severity!.label}][${category.label}]');
      if (confidence != null) {
        buffer.write('[CONFIDENCE: ${confidence!.label}]');
      }
    }

    buffer.write(' $message$locationLabel');
    buffer.write('\n→ Fix: $fix');
    if (risk != null) {
      buffer.write('\n→ Risk: $risk');
    }
    return buffer.toString();
  }
}
