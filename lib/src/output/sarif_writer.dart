import 'dart:convert';

import '../models/finding.dart';

/// Emits a SARIF 2.1.0 document from a list of [Finding]s.
///
/// SARIF (Static Analysis Results Interchange Format) is the industry standard
/// output format for SAST tools. GitHub Code Scanning, Azure DevOps, GitLab,
/// and most IDE plugins all consume SARIF directly, so supporting it is the
/// single biggest integration lever the scanner has.
///
/// The writer is intentionally dependency-free — the scanner ships with no
/// pub packages beyond the Dart SDK, and that stays true for SARIF output.
class SarifWriter {
  const SarifWriter({
    this.toolName = 'fluttersupabasehelper',
    this.toolVersion = kToolVersion,
    this.informationUri =
        'https://github.com/dilpreet-s-sidhu/flutter-security-scanner',
  });

  /// Keep in sync with `pubspec.yaml:version`. Tests pin this string so a
  /// version bump without updating the SARIF output (which CI systems cache
  /// and attribute by tool version) will fail loudly.
  static const String kToolVersion = '0.1.0';

  final String toolName;
  final String toolVersion;
  final String informationUri;

  /// Serialises [findings] as a pretty-printed SARIF 2.1.0 JSON document.
  ///
  /// The result is intentionally sorted and deterministic — two runs over the
  /// same repo must emit byte-identical SARIF so CI diff tools and baseline
  /// comparisons behave.
  String encode(
    List<Finding> findings, {
    String? targetPath,
  }) {
    // Build the rule dictionary. SARIF allows — and GitHub Code Scanning
    // prefers — the driver.rules array to list only rules that produced
    // results, so long as result.ruleIndex points into it. We go a step
    // further and also keep rule.id so consumers that ignore ruleIndex still
    // resolve correctly.
    final ruleIdOrder = <String>[];
    final ruleIndex = <String, int>{};
    final ruleMetadata = <String, _RuleMetadata>{};
    for (final finding in findings) {
      final code = finding.code;
      ruleMetadata.putIfAbsent(code, _RuleMetadata.new).absorb(finding);
      if (!ruleIndex.containsKey(code)) {
        ruleIndex[code] = ruleIdOrder.length;
        ruleIdOrder.add(code);
      }
    }

    final rules = [
      for (final id in ruleIdOrder)
        _ruleDescriptor(id, ruleMetadata[id]!),
    ];

    final results = [
      for (final finding in findings)
        _result(finding, ruleIndex[finding.code]!),
    ];

    final sarif = <String, Object?>{
      r'$schema':
          'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      'version': '2.1.0',
      'runs': <Map<String, Object?>>[
        <String, Object?>{
          'tool': <String, Object?>{
            'driver': <String, Object?>{
              'name': toolName,
              'version': toolVersion,
              'informationUri': informationUri,
              'rules': rules,
            },
          },
          if (targetPath != null)
            'originalUriBaseIds': <String, Object?>{
              'SRCROOT': <String, Object?>{
                'uri': _directoryUri(targetPath),
              },
            },
          'results': results,
          'columnKind': 'utf16CodeUnits',
        },
      ],
    };
    return const JsonEncoder.withIndent('  ').convert(sarif);
  }

  Map<String, Object?> _ruleDescriptor(String code, _RuleMetadata meta) {
    final level = _sarifLevelForSeverity(meta.dominantSeverity);
    return <String, Object?>{
      'id': code,
      'name': _toPascalCase(code),
      'shortDescription': <String, Object?>{
        'text': meta.sampleMessage,
      },
      'fullDescription': <String, Object?>{
        'text': meta.sampleRisk ?? meta.sampleMessage,
      },
      'helpUri':
          '$informationUri#${code.toLowerCase()}',
      'help': <String, Object?>{
        'text': meta.sampleFix,
      },
      'defaultConfiguration': <String, Object?>{
        'level': level,
      },
      'properties': <String, Object?>{
        'category': meta.sampleCategory.label.toLowerCase(),
        if (meta.sampleConfidence != null)
          'confidence': meta.sampleConfidence!.label.toLowerCase(),
        'tags': <String>[
          'security',
          meta.sampleCategory.label.toLowerCase(),
        ],
      },
    };
  }

  Map<String, Object?> _result(Finding finding, int ruleIdx) {
    final locations = <Map<String, Object?>>[];
    if (finding.filePath != null) {
      final region = <String, Object?>{};
      if (finding.line != null && finding.line! > 0) {
        region['startLine'] = finding.line;
      }
      locations.add(<String, Object?>{
        'physicalLocation': <String, Object?>{
          'artifactLocation': <String, Object?>{
            'uri': finding.filePath,
            'uriBaseId': 'SRCROOT',
          },
          if (region.isNotEmpty) 'region': region,
        },
      });
    }

    final properties = <String, Object?>{
      'fix': finding.fix,
      'category': finding.category.label.toLowerCase(),
      if (finding.risk != null) 'risk': finding.risk,
      if (finding.confidence != null)
        'confidence': finding.confidence!.label.toLowerCase(),
      if (finding.severity != null)
        'severity': finding.severity!.label.toLowerCase(),
      'isSuggestion': finding.isSuggestion,
    };

    final fingerprint = _fingerprint(finding);

    return <String, Object?>{
      'ruleId': finding.code,
      'ruleIndex': ruleIdx,
      'level': _sarifLevelForSeverity(finding.severity),
      'message': <String, Object?>{
        'text': finding.message,
      },
      if (locations.isNotEmpty) 'locations': locations,
      'partialFingerprints': <String, Object?>{
        'primaryLocationLineHash/v1': fingerprint,
      },
      'properties': properties,
    };
  }

  static String _sarifLevelForSeverity(FindingSeverity? severity) {
    return switch (severity) {
      FindingSeverity.high => 'error',
      FindingSeverity.medium => 'warning',
      FindingSeverity.low => 'note',
      null => 'none',
    };
  }

  static String _toPascalCase(String code) {
    final parts = code.split(RegExp(r'[-_]'));
    return parts
        .where((p) => p.isNotEmpty)
        .map((p) => p[0].toUpperCase() + p.substring(1).toLowerCase())
        .join();
  }

  static String _directoryUri(String path) {
    var clean = path.replaceAll(r'\\', '/');
    if (!clean.endsWith('/')) {
      clean = '$clean/';
    }
    return clean;
  }

  /// Stable fingerprint for a finding. Used in SARIF
  /// `partialFingerprints.primaryLocationLineHash/v1` so CI systems (notably
  /// GitHub Code Scanning) can match the same finding across runs even when
  /// the line number shifts slightly.
  ///
  /// Implemented as FNV-1a 64-bit over rule code + file path + message. We
  /// intentionally exclude the line number so a cosmetic reformat above the
  /// finding does not generate a new fingerprint and reopen the alert.
  static String _fingerprint(Finding finding) {
    final input = <Object?>[
      finding.code,
      finding.filePath ?? '',
      finding.message,
    ].join('\u0001');
    return _fnv1a64Hex(input);
  }

  static String _fnv1a64Hex(String input) {
    // 64-bit FNV-1a implemented with BigInt arithmetic to stay dependency-free
    // and deterministic across Dart runtimes. Only called once per finding so
    // the BigInt overhead is negligible compared to JSON encoding.
    final prime = BigInt.parse('0x100000001b3');
    final mask = BigInt.parse('0xffffffffffffffff');
    var hash = BigInt.parse('0xcbf29ce484222325');
    final bytes = utf8.encode(input);
    for (final byte in bytes) {
      hash = ((hash ^ BigInt.from(byte)) * prime) & mask;
    }
    return hash.toRadixString(16).padLeft(16, '0');
  }
}

/// Aggregated per-rule metadata built while walking the findings list. Used to
/// populate the `tool.driver.rules` array with sensible description/config
/// defaults even though rule objects themselves do not currently carry prose.
class _RuleMetadata {
  _RuleMetadata();

  String? _sampleMessage;
  String? _sampleFix;
  String? _sampleRisk;
  FindingCategory _sampleCategory = FindingCategory.security;
  FindingConfidence? _sampleConfidence;
  final Map<FindingSeverity, int> _severityCounts = {};

  void absorb(Finding finding) {
    _sampleMessage ??= finding.message;
    _sampleFix ??= finding.fix;
    _sampleRisk ??= finding.risk;
    _sampleCategory = finding.category;
    _sampleConfidence ??= finding.confidence;
    final severity = finding.severity;
    if (severity != null) {
      _severityCounts[severity] = (_severityCounts[severity] ?? 0) + 1;
    }
  }

  String get sampleMessage => _sampleMessage ?? '(no description)';
  String get sampleFix => _sampleFix ?? '';
  String? get sampleRisk => _sampleRisk;
  FindingCategory get sampleCategory => _sampleCategory;
  FindingConfidence? get sampleConfidence => _sampleConfidence;

  /// Picks the highest-severity level the rule produced in this run. Used as
  /// the SARIF `defaultConfiguration.level` — individual results still carry
  /// their own level so mixed-severity rules (e.g. `generic-secret`) stay
  /// accurate per result.
  FindingSeverity? get dominantSeverity {
    if (_severityCounts.isEmpty) return null;
    FindingSeverity? best;
    for (final sev in _severityCounts.keys) {
      if (best == null || sev.sortOrder < best.sortOrder) {
        best = sev;
      }
    }
    return best;
  }
}
