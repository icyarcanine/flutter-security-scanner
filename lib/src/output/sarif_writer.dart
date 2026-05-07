import 'dart:convert';

import '../models/finding.dart';
import 'finding_fingerprint.dart';

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

  /// Maximum chars to keep on a single embedded snippet line. Minified
  /// bundles can produce multi-MB single lines; truncating keeps the SARIF
  /// log within sane size budgets without changing the surrounding shape.
  static const int kMaxSnippetLineChars = 320;

  /// Serialises [findings] as a pretty-printed SARIF 2.1.0 JSON document.
  ///
  /// Pass [fileLines] to embed `region.snippet.text` and `contextRegion`
  /// per §IN-2 so GitHub Code Scanning (and any other SARIF viewer) can
  /// render the surrounding source without round-tripping to disk. Keys
  /// are file paths exactly as they appear in `Finding.filePath`.
  ///
  /// The result is intentionally sorted and deterministic — two runs over the
  /// same repo must emit byte-identical SARIF so CI diff tools and baseline
  /// comparisons behave.
  String encode(
    List<Finding> findings, {
    String? targetPath,
    Map<String, List<String>>? fileLines,
  }) {
    final lines = fileLines ?? const <String, List<String>>{};
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
        _result(finding, ruleIndex[finding.code]!, lines),
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

  Map<String, Object?> _result(
    Finding finding,
    int ruleIdx,
    Map<String, List<String>> fileLines,
  ) {
    final locations = <Map<String, Object?>>[];
    if (finding.filePath != null) {
      final region = <String, Object?>{};
      if (finding.line != null && finding.line! > 0) {
        region['startLine'] = finding.line;
      }
      final snippets = _buildSnippets(
        fileLines[finding.filePath!],
        finding.line,
      );
      if (snippets != null) {
        region['snippet'] = <String, Object?>{'text': snippets.regionText};
      }
      locations.add(<String, Object?>{
        'physicalLocation': <String, Object?>{
          'artifactLocation': <String, Object?>{
            'uri': finding.filePath,
            'uriBaseId': 'SRCROOT',
          },
          if (region.isNotEmpty) 'region': region,
          if (snippets != null)
            'contextRegion': <String, Object?>{
              'startLine': snippets.contextStartLine,
              'endLine': snippets.contextEndLine,
              'snippet': <String, Object?>{'text': snippets.contextText},
            },
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
      if (finding.detectionMethod != null)
        'detectionMethod': finding.detectionMethod!.label,
      'confidenceReason': finding.confidenceReason,
      'isSuggestion': finding.isSuggestion,
    };

    final fingerprint = _fingerprint(finding);
    final codeFlows = _codeFlowsFor(finding);

    return <String, Object?>{
      'ruleId': finding.code,
      'ruleIndex': ruleIdx,
      'level': _sarifLevelForSeverity(finding.severity),
      'message': <String, Object?>{
        'text': finding.message,
      },
      if (locations.isNotEmpty) 'locations': locations,
      if (codeFlows != null) 'codeFlows': codeFlows,
      'partialFingerprints': <String, Object?>{
        'primaryLocationLineHash/v1': fingerprint,
      },
      'properties': properties,
    };
  }

  /// Builds the SARIF `codeFlows` array for a finding. Emits a full
  /// source→sink trace when the finding carries a [TaintTrace], or a
  /// single-step "finding location" flow when only the sink is known —
  /// consumers like GitHub Code Scanning render both styles.
  ///
  /// Returns null when there is no usable location information, so the
  /// emitted SARIF stays compact and the `codeFlows` key is omitted entirely
  /// instead of appearing as an empty list.
  List<Map<String, Object?>>? _codeFlowsFor(Finding finding) {
    final trace = finding.trace;
    if (trace != null && trace.steps.isNotEmpty) {
      final locations = <Map<String, Object?>>[];
      for (var i = 0; i < trace.steps.length; i++) {
        final step = trace.steps[i];
        final region = <String, Object?>{
          if (step.line > 0) 'startLine': step.line,
        };
        final stepText = step.message ??
            switch (step.kind) {
              'source' => 'Source: untrusted input enters here',
              'propagation' => 'Propagation: taint is carried through here',
              'sanitizer-bypass' =>
                'Sanitizer bypass: value passes an unsafe gate',
              'sink' => 'Sink: tainted value reaches a dangerous operation',
              _ => step.kind,
            };
        locations.add(<String, Object?>{
          'location': <String, Object?>{
            'physicalLocation': <String, Object?>{
              'artifactLocation': <String, Object?>{
                'uri': step.filePath,
                'uriBaseId': 'SRCROOT',
              },
              if (region.isNotEmpty) 'region': region,
            },
            'message': <String, Object?>{
              'text': '${i + 1}. $stepText',
            },
          },
          'nestingLevel': 0,
          'executionOrder': i + 1,
          'importance': step.kind == 'sink' || step.kind == 'source'
              ? 'essential'
              : 'important',
        });
      }
      return <Map<String, Object?>>[
        <String, Object?>{
          'message': <String, Object?>{
            'text': 'Data flow: '
                '${trace.steps.first.kind} → ${trace.steps.last.kind} '
                '(${trace.steps.length} step${trace.steps.length == 1 ? '' : 's'})',
          },
          'threadFlows': <Map<String, Object?>>[
            <String, Object?>{
              'locations': locations,
            },
          ],
        },
      ];
    }

    // No explicit trace — emit a minimal single-location flow so SARIF
    // viewers still have a structured anchor. Only useful when the finding
    // has a file + line; otherwise skip the codeFlows key entirely.
    final path = finding.filePath;
    final line = finding.line;
    if (path == null || line == null || line <= 0) {
      return null;
    }
    return <Map<String, Object?>>[
      <String, Object?>{
        'message': <String, Object?>{
          'text': 'Finding location',
        },
        'threadFlows': <Map<String, Object?>>[
          <String, Object?>{
            'locations': <Map<String, Object?>>[
              <String, Object?>{
                'location': <String, Object?>{
                  'physicalLocation': <String, Object?>{
                    'artifactLocation': <String, Object?>{
                      'uri': path,
                      'uriBaseId': 'SRCROOT',
                    },
                    'region': <String, Object?>{'startLine': line},
                  },
                  'message': <String, Object?>{
                    'text': finding.message,
                  },
                },
                'nestingLevel': 0,
                'executionOrder': 1,
                'importance': 'essential',
              },
            ],
          },
        ],
      },
    ];
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

  /// Stable fingerprint for a finding. Delegates to the shared helper so
  /// SARIF output and the baseline file use the same identifier.
  static String _fingerprint(Finding finding) => fingerprintFinding(finding);

  /// Returns `null` when the source isn't available or the line is out of
  /// range — callers should omit `snippet` and `contextRegion` rather than
  /// emit empty ones.
  static _Snippets? _buildSnippets(List<String>? lines, int? line) {
    if (lines == null || lines.isEmpty) return null;
    if (line == null || line <= 0 || line > lines.length) return null;
    final regionText = _clampLine(lines[line - 1]);
    final ctxStart = (line - 2).clamp(1, lines.length);
    final ctxEnd = (line + 2).clamp(1, lines.length);
    final ctxLines = <String>[
      for (var i = ctxStart - 1; i < ctxEnd; i++) _clampLine(lines[i]),
    ];
    return _Snippets(
      regionText: regionText,
      contextText: ctxLines.join('\n'),
      contextStartLine: ctxStart,
      contextEndLine: ctxEnd,
    );
  }

  static String _clampLine(String line) {
    if (line.length <= kMaxSnippetLineChars) return line;
    return '${line.substring(0, kMaxSnippetLineChars)}…';
  }
}

class _Snippets {
  const _Snippets({
    required this.regionText,
    required this.contextText,
    required this.contextStartLine,
    required this.contextEndLine,
  });
  final String regionText;
  final String contextText;
  final int contextStartLine;
  final int contextEndLine;
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
