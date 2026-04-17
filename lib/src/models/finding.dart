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

/// How a finding was produced. Kept in parallel with the VS Code extension's
/// `DetectionMethod` enum so both engines can claim the same set of
/// "how we found it" reasons in their output.
///
/// This exists to prevent the class of integrity bug where a regex-matched
/// hardcoded secret gets labelled "confirmed via taint analysis". Every
/// finding declares the mechanism that produced it, and the human-readable
/// confidence reason is derived from (confidence, detectionMethod).
enum FindingDetectionMethod {
  /// Intra-procedural taint tracking: a source flowed into a sink.
  taint,
  /// AST/structural pattern match.
  structural,
  /// Regex against a known signature.
  regex,
  /// Shannon entropy on a string literal.
  entropy,
  /// Inspection of a configuration file (manifest, plist, gradle, yaml).
  config,
  /// Repository filesystem state (e.g. `.env` not in `.gitignore`).
  filesystem,
  /// Ad-hoc heuristic — weakest signal.
  heuristic,
}

extension FindingDetectionMethodLabel on FindingDetectionMethod {
  String get label => switch (this) {
    FindingDetectionMethod.taint => 'taint',
    FindingDetectionMethod.structural => 'structural',
    FindingDetectionMethod.regex => 'regex',
    FindingDetectionMethod.entropy => 'entropy',
    FindingDetectionMethod.config => 'config',
    FindingDetectionMethod.filesystem => 'filesystem',
    FindingDetectionMethod.heuristic => 'heuristic',
  };
}

/// One hop in a source→sink trace. A [TaintTrace] is a non-empty list of
/// these; the first entry is the source, the last is the sink, and any
/// middle entries are intermediate propagation steps (assignment,
/// sanitizer bypass, etc.). Emitted in SARIF `codeFlows` so reviewers can
/// see *why* a finding was raised instead of trusting an unexplained claim.
class TaintStep {
  const TaintStep({
    required this.kind,
    required this.filePath,
    required this.line,
    this.message,
  });

  /// `source` | `propagation` | `sanitizer-bypass` | `sink`.
  final String kind;
  final String filePath;
  final int line;
  final String? message;

  Map<String, Object?> toJson() => <String, Object?>{
        'kind': kind,
        'file': filePath,
        'line': line,
        if (message != null) 'message': message,
      };
}

/// An ordered list of [TaintStep]s describing how an untrusted value reached
/// a dangerous sink. Always has length ≥ 2 when emitted by a taint rule
/// (source + sink). Structural rules may emit length 1 (the finding point
/// itself) as a SARIF-friendly "single code flow" so diff tools still have
/// a location to anchor on.
class TaintTrace {
  const TaintTrace(this.steps);
  final List<TaintStep> steps;

  Map<String, Object?> toJson() => <String, Object?>{
        'steps': steps.map((s) => s.toJson()).toList(),
      };
}

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
    this.detectionMethod,
    this.trace,
    this.filePath,
    this.line,
  });

  final FindingSeverity? severity;
  final FindingCategory category;
  final FindingConfidence? confidence;

  /// How this finding was produced. When absent, consumers should treat the
  /// detection mechanism as "unspecified heuristic" rather than assuming
  /// taint analysis — the field is explicit precisely to avoid that kind of
  /// silent overclaim in the output.
  final FindingDetectionMethod? detectionMethod;

  /// Optional source→sink trace. When present, SARIF output emits a
  /// `codeFlows` entry so reviewers can follow the data path instead of
  /// trusting an unexplained "taint analysis" claim.
  final TaintTrace? trace;

  final String code;
  final String message;
  final String fix;

  /// One-line explanation of what goes wrong if this issue is ignored.
  /// Shown in terminal output when present.
  final String? risk;

  final String? filePath;
  final int? line;

  bool get isSuggestion => category == FindingCategory.suggestion;

  /// Human-readable explanation of the confidence level, derived from BOTH
  /// the confidence level AND the detection method. Kept in sync with the
  /// VS Code extension's `confidenceReason()` so the two engines produce
  /// identical explanations for the same (confidence, method) pair.
  String get confidenceReason {
    final c = confidence;
    if (c == null) return 'Confidence not assessed';
    final m = detectionMethod ?? FindingDetectionMethod.heuristic;
    switch (c) {
      case FindingConfidence.high:
        return switch (m) {
          FindingDetectionMethod.taint =>
            'User-controlled input flows into a dangerous sink (confirmed via intra-procedural taint analysis)',
          FindingDetectionMethod.structural =>
            'Unambiguous AST match for a dangerous construct',
          FindingDetectionMethod.regex =>
            'Regex match against a known-bad signature with high specificity',
          FindingDetectionMethod.entropy =>
            'High-entropy string matching a known credential format',
          FindingDetectionMethod.config =>
            'Confirmed from configuration file contents',
          FindingDetectionMethod.filesystem =>
            'Confirmed from repository filesystem state',
          FindingDetectionMethod.heuristic =>
            'High-confidence heuristic match',
        };
      case FindingConfidence.medium:
        return switch (m) {
          FindingDetectionMethod.taint =>
            'Indirect taint flow through an opaque wrapper (not fully confirmed)',
          FindingDetectionMethod.structural =>
            'Suspicious AST pattern without data-flow confirmation',
          FindingDetectionMethod.regex =>
            'Regex match that may have legitimate uses — review in context',
          FindingDetectionMethod.entropy =>
            'Moderately entropic string in a sensitive position',
          FindingDetectionMethod.config =>
            'Configuration pattern that is commonly but not always unsafe',
          FindingDetectionMethod.filesystem =>
            'Filesystem state that often but not always indicates a problem',
          FindingDetectionMethod.heuristic =>
            'Medium-confidence heuristic — verify in context',
        };
      case FindingConfidence.low:
        return switch (m) {
          FindingDetectionMethod.taint => 'Weak taint signal — may be a false positive',
          FindingDetectionMethod.structural =>
            'Structural hint only — verify manually',
          FindingDetectionMethod.regex =>
            'Heuristic regex match — may be a false positive, verify manually',
          FindingDetectionMethod.entropy =>
            'Entropy-based match — may be a false positive, verify manually',
          FindingDetectionMethod.config => 'Configuration hint — verify manually',
          FindingDetectionMethod.filesystem => 'Filesystem hint — verify manually',
          FindingDetectionMethod.heuristic =>
            'Low-confidence heuristic — verify manually',
        };
    }
  }

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

  /// Stable JSON representation suitable for `--json` CLI output and CI
  /// pipelines. Keys are intentionally snake_case so downstream tools written
  /// in any language can parse them without re-mapping.
  Map<String, Object?> toJson() {
    return <String, Object?>{
      'code': code,
      'category': category.label.toLowerCase(),
      'severity': severity?.label.toLowerCase(),
      'confidence': confidence?.label.toLowerCase(),
      if (detectionMethod != null) 'detection_method': detectionMethod!.label,
      'confidence_reason': confidenceReason,
      'message': message,
      'fix': fix,
      if (risk != null) 'risk': risk,
      if (filePath != null) 'file': filePath,
      if (line != null) 'line': line,
      if (trace != null) 'trace': trace!.toJson(),
      'is_suggestion': isSuggestion,
    };
  }
}
