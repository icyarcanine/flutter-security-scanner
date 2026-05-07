import '../models/finding.dart';

/// In-repo configuration for the scanner, loaded from `.fshrc.yaml`,
/// `.fshrc.yml`, or `.fshrc.json` at the project root.
///
/// The config file is how teams encode their project-specific tuning without
/// wrapping the CLI in shell glue: rules to disable, path globs to exclude,
/// severity tweaks to reflect the team's risk appetite, and defaults for the
/// `--fail-on` / `--no-suggestions` behaviour.
///
/// Command-line flags always override config values so ad-hoc CI overrides
/// stay simple (`dart run … --fail-on=high` beats whatever the file says).
class ScannerConfig {
  const ScannerConfig({
    this.disabledRules = const <String>{},
    this.severityOverrides = const <String, FindingSeverity>{},
    this.excludePatterns = const <String>[],
    this.ruleExcludePatterns = const <String, List<String>>{},
    this.failOn,
    this.includeSuggestions,
    this.sourcePath,
  });

  /// Rules that should not be evaluated at all. Matching is by rule code
  /// (e.g. `hardcoded-secrets`).
  final Set<String> disabledRules;

  /// Per-rule severity remap. Use sparingly — downgrading a HIGH to a LOW is
  /// almost always a sign the finding should be excluded instead of silenced.
  final Map<String, FindingSeverity> severityOverrides;

  /// Global path globs to exclude from the walker. Matched against the
  /// project-relative POSIX-style path.
  final List<String> excludePatterns;

  /// Per-rule exclude globs. Findings produced by rule `code` whose file path
  /// matches one of the globs are dropped before being reported.
  final Map<String, List<String>> ruleExcludePatterns;

  /// Default `--fail-on` threshold when the CLI flag is not supplied.
  final FindingSeverity? failOn;

  /// Default `--no-suggestions` behaviour when the CLI flag is not supplied.
  /// `null` means "use the CLI default (true)".
  final bool? includeSuggestions;

  /// The on-disk path the config was loaded from, if any. Used for error
  /// messages and `--print-config` introspection.
  final String? sourcePath;

  static const ScannerConfig empty = ScannerConfig();

  bool get isEmpty =>
      disabledRules.isEmpty &&
      severityOverrides.isEmpty &&
      excludePatterns.isEmpty &&
      ruleExcludePatterns.isEmpty &&
      failOn == null &&
      includeSuggestions == null;

  /// True when the rule with `code` has been disabled entirely.
  bool isRuleDisabled(String code) => disabledRules.contains(code);

  /// Severity override for `code`, or `null` if none was set.
  FindingSeverity? severityFor(String code) => severityOverrides[code];

  /// True when `relativePath` should be excluded from scanning globally.
  bool isPathExcluded(String relativePath) {
    for (final pattern in excludePatterns) {
      if (_globMatches(pattern, relativePath)) return true;
    }
    return false;
  }

  /// True when a finding from `code` in `relativePath` should be suppressed.
  /// Callers already know `relativePath` was NOT globally excluded.
  bool isRulePathExcluded(String code, String relativePath) {
    final patterns = ruleExcludePatterns[code];
    if (patterns == null) return false;
    for (final pattern in patterns) {
      if (_globMatches(pattern, relativePath)) return true;
    }
    return false;
  }

  /// Converts a raw parsed map (from YAML or JSON) into a [ScannerConfig].
  ///
  /// Unknown top-level keys are rejected with a [ConfigFormatException] rather
  /// than silently ignored — a typo in a config file is far more likely to
  /// mean "this rule should be disabled" than "ignore me", and silent failure
  /// there is catastrophic in a security tool.
  factory ScannerConfig.fromMap(
    Map<String, Object?> map, {
    String? sourcePath,
  }) {
    const knownKeys = <String>{
      'rules',
      'exclude',
      'fail_on',
      'include_suggestions',
    };

    for (final key in map.keys) {
      if (!knownKeys.contains(key)) {
        throw ConfigFormatException(
          'Unknown config key `$key`. '
          'Supported keys: ${knownKeys.join(", ")}.',
          sourcePath: sourcePath,
        );
      }
    }

    final exclude = <String>[];
    final rawExclude = map['exclude'];
    if (rawExclude != null) {
      if (rawExclude is! List) {
        throw ConfigFormatException(
          '`exclude` must be a list of glob patterns.',
          sourcePath: sourcePath,
        );
      }
      for (final entry in rawExclude) {
        if (entry is! String) {
          throw ConfigFormatException(
            '`exclude` entries must be strings (got `$entry`).',
            sourcePath: sourcePath,
          );
        }
        exclude.add(entry.trim());
      }
    }

    FindingSeverity? failOn;
    final rawFailOn = map['fail_on'];
    if (rawFailOn != null) {
      if (rawFailOn is! String) {
        throw ConfigFormatException(
          '`fail_on` must be one of high, medium, low.',
          sourcePath: sourcePath,
        );
      }
      failOn = _parseSeverity(rawFailOn, sourcePath, key: 'fail_on');
    }

    bool? includeSuggestions;
    final rawIncludeSuggestions = map['include_suggestions'];
    if (rawIncludeSuggestions != null) {
      if (rawIncludeSuggestions is! bool) {
        throw ConfigFormatException(
          '`include_suggestions` must be a boolean.',
          sourcePath: sourcePath,
        );
      }
      includeSuggestions = rawIncludeSuggestions;
    }

    final disabled = <String>{};
    final severity = <String, FindingSeverity>{};
    final ruleExcludes = <String, List<String>>{};

    final rawRules = map['rules'];
    if (rawRules != null) {
      if (rawRules is! Map) {
        throw ConfigFormatException(
          '`rules` must be a map keyed by rule code.',
          sourcePath: sourcePath,
        );
      }
      rawRules.forEach((key, value) {
        if (key is! String) {
          throw ConfigFormatException(
            '`rules` keys must be strings (rule codes).',
            sourcePath: sourcePath,
          );
        }
        final code = key.trim();
        if (code.isEmpty) {
          throw ConfigFormatException(
            'Empty rule code in `rules`.',
            sourcePath: sourcePath,
          );
        }

        if (value is bool) {
          if (!value) disabled.add(code);
          return;
        }
        if (value == null) {
          // `rules.<code>:` with no body — treat as no-op, not a disable.
          return;
        }
        if (value is String) {
          // Shorthand: `rules.<code>: off|disabled|error|warning|note`
          final lowered = value.trim().toLowerCase();
          if (lowered == 'off' || lowered == 'disabled') {
            disabled.add(code);
            return;
          }
          // Any other string is treated as a severity override, matching
          // the `severity:` sub-key so short configs stay readable.
          severity[code] = _parseSeverity(
            lowered,
            sourcePath,
            key: 'rules.$code',
          );
          return;
        }
        if (value is! Map) {
          throw ConfigFormatException(
            '`rules.$code` must be a boolean, string, or map.',
            sourcePath: sourcePath,
          );
        }

        for (final subKey in value.keys) {
          if (subKey is! String) {
            throw ConfigFormatException(
              '`rules.$code` sub-keys must be strings.',
              sourcePath: sourcePath,
            );
          }
        }

        final enabledValue = value['enabled'];
        if (enabledValue is bool && !enabledValue) {
          disabled.add(code);
        }

        final sevValue = value['severity'];
        if (sevValue != null) {
          if (sevValue is! String) {
            throw ConfigFormatException(
              '`rules.$code.severity` must be a string.',
              sourcePath: sourcePath,
            );
          }
          severity[code] = _parseSeverity(
            sevValue,
            sourcePath,
            key: 'rules.$code.severity',
          );
        }

        final excludeValue = value['exclude'];
        if (excludeValue != null) {
          if (excludeValue is! List) {
            throw ConfigFormatException(
              '`rules.$code.exclude` must be a list of glob patterns.',
              sourcePath: sourcePath,
            );
          }
          final patterns = <String>[];
          for (final entry in excludeValue) {
            if (entry is! String) {
              throw ConfigFormatException(
                '`rules.$code.exclude` entries must be strings.',
                sourcePath: sourcePath,
              );
            }
            patterns.add(entry.trim());
          }
          if (patterns.isNotEmpty) {
            ruleExcludes[code] = patterns;
          }
        }
      });
    }

    return ScannerConfig(
      disabledRules: disabled,
      severityOverrides: severity,
      excludePatterns: exclude,
      ruleExcludePatterns: ruleExcludes,
      failOn: failOn,
      includeSuggestions: includeSuggestions,
      sourcePath: sourcePath,
    );
  }

  static FindingSeverity _parseSeverity(
    String raw,
    String? sourcePath, {
    required String key,
  }) {
    switch (raw.trim().toLowerCase()) {
      case 'high':
      case 'error':
        return FindingSeverity.high;
      case 'medium':
      case 'warning':
        return FindingSeverity.medium;
      case 'low':
      case 'note':
      case 'info':
        return FindingSeverity.low;
    }
    throw ConfigFormatException(
      '`$key` must be one of high, medium, low (got `$raw`).',
      sourcePath: sourcePath,
    );
  }
}

/// Thrown when `.fshrc` parsing or validation fails. The scanner's CLI
/// surfaces these as `exit 2` so CI treats a broken config the same way it
/// would a broken command-line flag — fail fast.
class ConfigFormatException implements Exception {
  ConfigFormatException(this.message, {this.sourcePath, this.line});

  final String message;
  final String? sourcePath;
  final int? line;

  @override
  String toString() {
    final location = <String>[];
    if (sourcePath != null) location.add(sourcePath!);
    if (line != null) location.add('line $line');
    final prefix = location.isEmpty ? '' : '${location.join(":")}: ';
    return '$prefix$message';
  }
}

/// Minimal glob matcher used by [ScannerConfig.isPathExcluded] /
/// [ScannerConfig.isRulePathExcluded]. Supports the gitignore-ish subset a
/// config file actually needs:
///
/// * `*`  — any number of non-slash characters.
/// * `**` — any number of characters including slashes.
/// * `?`  — exactly one non-slash character.
/// * Literal path components.
///
/// A pattern containing no wildcards matches when it is a path prefix (so
/// `build` matches `build/main.dart`) — this is the shape users intuitively
/// expect from `.gitignore`-style configs.
bool _globMatches(String pattern, String path) {
  if (pattern.isEmpty) return false;
  var p = pattern.replaceAll(r'\\', '/').trim();
  final target = path.replaceAll(r'\\', '/');

  // Strip leading `./`.
  if (p.startsWith('./')) p = p.substring(2);

  final hasWildcard = p.contains('*') || p.contains('?');
  if (!hasWildcard) {
    // Directory-style shorthand: `build` → everything under `build/`.
    if (target == p) return true;
    if (target.startsWith('$p/')) return true;
    return false;
  }

  // If the pattern ends with `/` treat it as `prefix/**`.
  if (p.endsWith('/')) {
    p = '$p**';
  }

  final regex = _globToRegex(p);
  return RegExp('^$regex\$').hasMatch(target);
}

String _globToRegex(String pattern) {
  final buf = StringBuffer();
  var i = 0;
  while (i < pattern.length) {
    final ch = pattern[i];
    if (ch == '*') {
      if (i + 1 < pattern.length && pattern[i + 1] == '*') {
        // `**/` and `/**` both collapse a path boundary.
        i += 2;
        if (i < pattern.length && pattern[i] == '/') {
          buf.write('(?:.*/)?');
          i++;
        } else {
          buf.write('.*');
        }
      } else {
        buf.write('[^/]*');
        i++;
      }
    } else if (ch == '?') {
      buf.write('[^/]');
      i++;
    } else if (r'.+()|[]{}^$\'.contains(ch)) {
      buf
        ..write(r'\')
        ..write(ch);
      i++;
    } else {
      buf.write(ch);
      i++;
    }
  }
  return buf.toString();
}
