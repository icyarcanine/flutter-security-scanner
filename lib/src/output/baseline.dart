import 'dart:convert';
import 'dart:io';

import '../models/finding.dart';
import 'finding_fingerprint.dart';

/// A baseline file freezes the set of findings that exist at a point in time
/// so teams can adopt the scanner on an existing codebase without fixing
/// everything up front. Future runs load the baseline and suppress any
/// finding whose fingerprint is in it — only NEW findings break the build.
///
/// The file format is intentionally JSON-only: it is a machine artefact,
/// usually checked into the repo, and it does not need hand-editability. The
/// shape is versioned so future scanner releases can evolve the schema
/// without invalidating existing baselines.
class BaselineFile {
  BaselineFile({
    required this.generatedAt,
    required this.toolVersion,
    required this.entries,
  });

  /// Current baseline schema version. Bumped when the shape changes in a
  /// backwards-incompatible way so loaders can refuse unknown versions.
  static const int schemaVersion = 1;

  /// When the baseline was captured (ISO-8601). Purely informational.
  final String generatedAt;

  /// Scanner version that produced the baseline. If a future run sees a
  /// mismatch it still works — fingerprints do not depend on the scanner
  /// version — but the value is surfaced to help operators reason about
  /// drift between capture and check.
  final String toolVersion;

  /// The baseline rows. Each row carries the fingerprint plus enough
  /// identifying context that a human reviewing the JSON can tell what the
  /// row corresponds to.
  final List<BaselineEntry> entries;

  /// Fingerprints present in the baseline. Computed eagerly for O(1) lookup.
  Set<String> get fingerprints =>
      _fingerprintCache ??= {for (final e in entries) e.fingerprint};
  Set<String>? _fingerprintCache;

  bool containsFinding(Finding finding) =>
      fingerprints.contains(fingerprintFinding(finding));

  /// Applies the baseline to [findings]. Findings whose fingerprint matches a
  /// baseline entry are dropped; everything else passes through in the same
  /// order.
  List<Finding> filter(Iterable<Finding> findings) {
    if (fingerprints.isEmpty) return List.of(findings);
    return findings
        .where((f) => !fingerprints.contains(fingerprintFinding(f)))
        .toList();
  }

  /// Builds a [BaselineFile] from the current findings list. Used by
  /// `--write-baseline` to snapshot a fresh state.
  factory BaselineFile.fromFindings(
    Iterable<Finding> findings, {
    required String toolVersion,
    DateTime? now,
  }) {
    final sorted = findings.toList()
      ..sort((a, b) {
        final codeCompare = a.code.compareTo(b.code);
        if (codeCompare != 0) return codeCompare;
        final fileCompare = (a.filePath ?? '').compareTo(b.filePath ?? '');
        if (fileCompare != 0) return fileCompare;
        return a.message.compareTo(b.message);
      });
    final entries = <BaselineEntry>[
      for (final finding in sorted)
        BaselineEntry(
          fingerprint: fingerprintFinding(finding),
          code: finding.code,
          filePath: finding.filePath,
          message: finding.message,
          severity: finding.severity?.label.toLowerCase(),
        ),
    ];
    return BaselineFile(
      generatedAt: (now ?? DateTime.now().toUtc()).toIso8601String(),
      toolVersion: toolVersion,
      entries: entries,
    );
  }

  /// Reads a baseline file from disk. Returns [BaselineFile] with an empty
  /// entries list when the file is missing — callers can treat absence as
  /// "no suppression" without special-casing.
  factory BaselineFile.loadFromFile(String path) {
    final file = File(path);
    if (!file.existsSync()) {
      return BaselineFile(
        generatedAt: '',
        toolVersion: '',
        entries: const <BaselineEntry>[],
      );
    }

    final raw = file.readAsStringSync().trim();
    if (raw.isEmpty) {
      return BaselineFile(
        generatedAt: '',
        toolVersion: '',
        entries: const <BaselineEntry>[],
      );
    }

    dynamic decoded;
    try {
      decoded = jsonDecode(raw);
    } on FormatException catch (e) {
      throw BaselineFormatException(
        'Baseline file $path is not valid JSON: ${e.message}',
        sourcePath: path,
      );
    }

    if (decoded is! Map) {
      throw BaselineFormatException(
        'Baseline root must be a JSON object.',
        sourcePath: path,
      );
    }

    final schema = decoded['schema_version'];
    if (schema is int && schema > schemaVersion) {
      throw BaselineFormatException(
        'Baseline file $path was produced by a newer scanner '
        '(schema_version=$schema). Upgrade fluttersupabasehelper or '
        'regenerate the baseline.',
        sourcePath: path,
      );
    }

    final rawEntries = decoded['fingerprints'];
    if (rawEntries != null && rawEntries is! List) {
      throw BaselineFormatException(
        'Baseline `fingerprints` must be a list.',
        sourcePath: path,
      );
    }

    final entries = <BaselineEntry>[];
    if (rawEntries is List) {
      for (final row in rawEntries) {
        if (row is! Map) {
          throw BaselineFormatException(
            'Baseline entry is not an object.',
            sourcePath: path,
          );
        }
        final fingerprint = row['hash'];
        if (fingerprint is! String || fingerprint.isEmpty) {
          throw BaselineFormatException(
            'Baseline entry missing `hash`.',
            sourcePath: path,
          );
        }
        entries.add(
          BaselineEntry(
            fingerprint: fingerprint,
            code: row['code'] is String ? row['code'] as String : '',
            filePath: row['file'] is String ? row['file'] as String : null,
            message:
                row['message'] is String ? row['message'] as String : '',
            severity: row['severity'] is String
                ? row['severity'] as String
                : null,
          ),
        );
      }
    }

    return BaselineFile(
      generatedAt:
          decoded['generated_at'] is String ? decoded['generated_at'] as String : '',
      toolVersion:
          decoded['tool_version'] is String ? decoded['tool_version'] as String : '',
      entries: entries,
    );
  }

  /// Serialises the baseline to JSON. Output is pretty-printed for diff
  /// readability — a committed baseline should produce reviewable diffs, not
  /// single-line walls of text.
  String encode() {
    final payload = <String, Object?>{
      'schema_version': schemaVersion,
      'tool': 'fluttersupabasehelper',
      'tool_version': toolVersion,
      'generated_at': generatedAt,
      'total': entries.length,
      'fingerprints': <Map<String, Object?>>[
        for (final entry in entries) entry.toJson(),
      ],
    };
    return const JsonEncoder.withIndent('  ').convert(payload);
  }

  /// Writes the baseline to [path]. Callers are responsible for surfacing
  /// any I/O exceptions (the CLI turns these into a clean `exit 2`).
  void writeToFile(String path) {
    final file = File(path);
    file.parent.createSync(recursive: true);
    file.writeAsStringSync('${encode()}\n');
  }
}

class BaselineEntry {
  const BaselineEntry({
    required this.fingerprint,
    required this.code,
    required this.message,
    this.filePath,
    this.severity,
  });

  final String fingerprint;
  final String code;
  final String? filePath;
  final String message;
  final String? severity;

  Map<String, Object?> toJson() {
    return <String, Object?>{
      'hash': fingerprint,
      'code': code,
      if (filePath != null) 'file': filePath,
      if (severity != null) 'severity': severity,
      'message': message,
    };
  }
}

class BaselineFormatException implements Exception {
  BaselineFormatException(this.message, {this.sourcePath});

  final String message;
  final String? sourcePath;

  @override
  String toString() {
    if (sourcePath == null) return message;
    return '$sourcePath: $message';
  }
}
