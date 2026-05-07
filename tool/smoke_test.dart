import 'dart:convert';
import 'dart:io';

import 'package:fluttersupabasehelper/fluttersupabasehelper.dart';

void main() {
  final failures = <String>[];

  _runCase(
    name: 'broken_app',
    includeSuggestions: true,
    expectedCodes: {
      'hardcoded-secrets',
      'committed-env',
      'sensitive-logging',
      'client-side-trust',
      'file-upload-validation',
      'public-storage',
      'multiple-supabase-clients',
      'debug-print',
      'missing-rls-awareness',
      'table-ownership-filter',
      'rls-policy-suggestion',
    },
    failures: failures,
  );

  _runCase(
    name: 'missing_init_app',
    includeSuggestions: false,
    expectedCodes: {'improper-initialization'},
    expectedIssueCount: 1,
    failures: failures,
  );

  _runCase(
    name: 'clean_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'nested_env_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'env_template_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'docs_only_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'migration_schema_only_app',
    includeSuggestions: false,
    expectedCodes: {'missing-rls-awareness', 'table-ownership-filter'},
    failures: failures,
  );

  _runCase(
    name: 'safe_current_user_alias_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'exact_path_gitignore_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'local_dev_url_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'lan_dev_url_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'negated_gitignore_app',
    includeSuggestions: false,
    expectedCodes: {'committed-env'},
    expectedIssueCount: 1,
    failures: failures,
  );

  _runCase(
    name: 'generic_api_key_app',
    includeSuggestions: false,
    expectedCodes: {'generic-secret', 'high-entropy-secret'},
    failures: failures,
  );

  _runCase(
    name: 'service_role_in_client_app',
    includeSuggestions: false,
    expectedCodes: {
      'supabase-service-role-key-in-client',
      'missing-env-vars',
      'hardcoded-secrets',
    },
    failures: failures,
  );

  _runCase(
    name: 'supabase_service_role_in_docs_app',
    includeSuggestions: false,
    expectedCodes: {'generic-secret'},
    failures: failures,
  );

  _runCase(
    name: 'supabase_rpc_injection_app',
    includeSuggestions: false,
    expectedCodes: {'supabase-rpc-injection'},
    failures: failures,
  );

  _runCase(
    name: 'realtime_no_filter_app',
    includeSuggestions: false,
    expectedCodes: {'supabase-realtime-filter'},
    expectedIssueCount: 1,
    failures: failures,
  );

  _runCase(
    name: 'realtime_filter_ok_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'signed_url_ttl_app',
    includeSuggestions: false,
    expectedCodes: {'supabase-signed-url-ttl'},
    failures: failures,
  );

  _runCase(
    name: 'signed_url_ttl_ok_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'edge_function_secrets_app',
    includeSuggestions: false,
    expectedCodes: {'supabase-edge-function-secrets'},
    failures: failures,
  );

  _runCase(
    name: 'edge_function_secrets_ok_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'private_files_bucket_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'non_supabase_builder_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'messages_or_filter_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'fallback_userid_app',
    includeSuggestions: false,
    expectedCodes: {'client-side-trust'},
    expectedIssueCount: 1,
    failures: failures,
  );

  _runCase(
    name: 'tests_only_secrets_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'helper_validation_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'helper_definition_only_app',
    includeSuggestions: false,
    expectedCodes: {'file-upload-validation'},
    expectedIssueCount: 1,
    failures: failures,
  );

  _runCase(
    name: 'public_token_bucket_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'comment_supabase_builder_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'readme_rls_only_app',
    includeSuggestions: false,
    expectedCodes: {'missing-rls-awareness', 'table-ownership-filter'},
    failures: failures,
  );

  _runCase(
    name: 'placeholder_env_app',
    includeSuggestions: false,
    expectedCodes: {
      'placeholder-env-value',
      'missing-rls-awareness',
      'table-ownership-filter',
    },
    failures: failures,
  );

  _runCase(
    name: 'multiline_logging_app',
    includeSuggestions: false,
    expectedCodes: {
      'improper-initialization',
      'sensitive-logging',
      'debug-print',
    },
    failures: failures,
  );

  _runCase(
    name: 'weak_rls_app',
    includeSuggestions: false,
    expectedCodes: {
      'improper-initialization',
      'missing-rls-awareness',
      'table-ownership-filter',
    },
    failures: failures,
  );

  _runCase(
    name: 'storage_path_app',
    includeSuggestions: false,
    expectedCodes: {
      'improper-initialization',
      'public-storage',
      'file-upload-validation',
    },
    failures: failures,
  );

  _runCase(
    name: 'adversarial_app',
    includeSuggestions: false,
    expectedCodes: {
      'improper-initialization',
      'sensitive-logging',
      'debug-print',
    },
    failures: failures,
  );

  _runCase(
    name: 'extreme_edge_cases_app',
    includeSuggestions: false,
    expectedCodes: {'improper-initialization', 'debug-print'},
    failures: failures,
  );

  _runCase(
    name: 'path_traversal_app',
    includeSuggestions: false,
    expectedCodes: {'path-traversal'},
    failures: failures,
  );

  _runCase(
    name: 'unobscured_password_app',
    includeSuggestions: false,
    expectedCodes: {'unobscured-password-field'},
    failures: failures,
  );

  _runCase(
    name: 'gradle_secrets_app',
    includeSuggestions: false,
    expectedCodes: {'gradle-secrets'},
    failures: failures,
  );

  _runCase(
    name: 'release_hardening_app',
    includeSuggestions: false,
    expectedCodes: {'release-hardening'},
    failures: failures,
  );

  _runCase(
    name: 'biometric_auth_app',
    includeSuggestions: false,
    expectedCodes: {'biometric-auth'},
    failures: failures,
  );

  _runCase(
    name: 'biometric_auth_ok_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'sqflite_unencrypted_app',
    includeSuggestions: false,
    expectedCodes: {'insecure-storage'},
    failures: failures,
  );

  _runCase(
    name: 'sqflite_sqlcipher_ok_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'hive_unencrypted_app',
    includeSuggestions: false,
    expectedCodes: {'insecure-storage'},
    failures: failures,
  );

  _runCase(
    name: 'hive_encrypted_ok_app',
    includeSuggestions: false,
    expectedCodes: const {},
    expectedIssueCount: 0,
    failures: failures,
  );

  _runCase(
    name: 'weak_crypto_app',
    includeSuggestions: false,
    expectedCodes: {'weak-crypto'},
    failures: failures,
  );

  _runCase(
    name: 'clipboard_exposure_app',
    includeSuggestions: false,
    expectedCodes: {'clipboard-exposure'},
    failures: failures,
  );

  _runCase(
    name: 'insecure_manifest_app',
    includeSuggestions: false,
    expectedCodes: {'platform-security'},
    failures: failures,
  );

  _runCase(
    name: 'platform_security_deep_app',
    includeSuggestions: false,
    expectedCodes: {'platform-security'},
    failures: failures,
  );

  _runCase(
    name: 'webview_insecure_app',
    includeSuggestions: false,
    expectedCodes: {'webview-security'},
    failures: failures,
  );

  _runCase(
    name: 'missing_cert_pinning_app',
    includeSuggestions: false,
    expectedCodes: {'missing-cert-pinning'},
    failures: failures,
  );

  _runCase(
    name: 'deep_link_app',
    includeSuggestions: false,
    expectedCodes: {'deep-link-validation'},
    failures: failures,
  );

  _runCase(
    name: 'insecure_storage_app',
    includeSuggestions: false,
    expectedCodes: {'insecure-storage'},
    failures: failures,
  );

  _runCase(
    name: 'plaintext_http_app',
    includeSuggestions: false,
    expectedCodes: {'plaintext-http'},
    failures: failures,
  );

  _runCase(
    name: 'pii_logging_app',
    includeSuggestions: false,
    expectedCodes: {'sensitive-logging'},
    failures: failures,
  );

  _runCase(
    name: 'config_file_app',
    includeSuggestions: true,
    expectedCodes: {'supabase-signed-url-ttl'},
    expectedIssueCount: 1,
    failures: failures,
  );
  _runConfigCase(failures);

  _runMalformedEncodingCase(failures);
  _runSarifCase(failures);
  _runBaselineCase(failures);

  if (failures.isNotEmpty) {
    stderr.writeln('Smoke test failures:');
    for (final failure in failures) {
      stderr.writeln('- $failure');
    }
    exit(1);
  }

  stdout.writeln('Smoke tests passed.');
}

void _runCase({
  required String name,
  required bool includeSuggestions,
  required Set<String> expectedCodes,
  int? expectedIssueCount,
  required List<String> failures,
}) {
  final path = 'test/fixtures/$name';
  // Mirror CLI behaviour: auto-load .fshrc.{yaml,yml,json} from the fixture
  // root so config-file fixtures exercise the real code path. Fixtures
  // without a config file get ScannerConfig.empty (the previous behaviour).
  final config = const ConfigLoader().loadFromRoot(path);
  final report = ProjectScanner(
    includeSuggestions: includeSuggestions,
    config: config,
  ).scan(path);

  final actualCodes = report.findings.map((finding) => finding.code).toSet();
  for (final expected in expectedCodes) {
    if (!actualCodes.contains(expected)) {
      failures.add('$name is missing expected finding code `$expected`.');
    }
  }

  if (expectedIssueCount != null) {
    final issueCount = report.findings
        .where((finding) => !finding.isSuggestion)
        .length;
    if (issueCount != expectedIssueCount) {
      failures.add(
        '$name expected $expectedIssueCount issue(s) but found $issueCount.',
      );
    }
  }

  if (expectedIssueCount == 0) {
    final issueCount = report.findings
        .where((finding) => !finding.isSuggestion)
        .length;
    if (issueCount != 0) {
      failures.add('$name should be clean but produced:');
      for (final finding in report.findings) {
        failures.add('  ${finding.toConsoleBlock()}');
      }
    }
  }

  if (!Directory(path).existsSync()) {
    failures.add('Fixture directory $path does not exist.');
  }
}

void _runSarifCase(List<String> failures) {
  // SARIF output is the single biggest CI integration lever this tool has, so
  // we pin the shape of the emitted document. The test runs the real scanner
  // on a fixture we know produces multiple findings, then asserts the JSON
  // parses and carries the SARIF 2.1.0 contract GitHub Code Scanning (and
  // other SAST consumers) expect.
  const fixturePath = 'test/fixtures/edge_function_secrets_app';
  try {
    final report = const ProjectScanner(
      includeSuggestions: false,
    ).scan(fixturePath);

    if (report.findings.isEmpty) {
      failures.add(
        'sarif smoke case: $fixturePath produced zero findings, cannot exercise writer.',
      );
      return;
    }

    const writer = SarifWriter();
    final encoded = writer.encode(report.findings, targetPath: fixturePath);
    final decoded = jsonDecode(encoded);
    if (decoded is! Map) {
      failures.add('sarif smoke case: top-level value is not a JSON object.');
      return;
    }

    if (decoded[r'$schema'] is! String) {
      failures.add('sarif smoke case: `\$schema` missing or not a string.');
    }
    if (decoded['version'] != '2.1.0') {
      failures.add(
        'sarif smoke case: expected version "2.1.0" but saw ${decoded['version']}.',
      );
    }

    final runs = decoded['runs'];
    if (runs is! List || runs.isEmpty) {
      failures.add('sarif smoke case: `runs` missing or empty.');
      return;
    }
    final run = runs.first;
    if (run is! Map) {
      failures.add('sarif smoke case: `runs[0]` is not an object.');
      return;
    }

    final driver = (run['tool'] as Map?)?['driver'];
    if (driver is! Map) {
      failures.add('sarif smoke case: `tool.driver` missing.');
      return;
    }
    if (driver['name'] != 'fluttersupabasehelper') {
      failures.add(
        'sarif smoke case: driver name is ${driver['name']}, expected fluttersupabasehelper.',
      );
    }
    final rules = driver['rules'];
    if (rules is! List || rules.isEmpty) {
      failures.add('sarif smoke case: `driver.rules` missing or empty.');
    } else {
      final first = rules.first;
      if (first is! Map ||
          first['id'] is! String ||
          first['shortDescription'] is! Map) {
        failures.add('sarif smoke case: rule entry is missing required keys.');
      }
    }

    final results = run['results'];
    if (results is! List || results.isEmpty) {
      failures.add('sarif smoke case: `results` missing or empty.');
      return;
    }
    for (final result in results) {
      if (result is! Map) {
        failures.add('sarif smoke case: result entry is not an object.');
        continue;
      }
      if (result['ruleId'] is! String) {
        failures.add('sarif smoke case: result missing ruleId.');
      }
      if (result['message'] is! Map ||
          (result['message'] as Map)['text'] is! String) {
        failures.add('sarif smoke case: result message is not {text: ...}.');
      }
      final level = result['level'];
      if (level is! String ||
          !const {'error', 'warning', 'note', 'none'}.contains(level)) {
        failures.add(
          'sarif smoke case: unexpected result level $level.',
        );
      }
      final fingerprints = result['partialFingerprints'];
      if (fingerprints is! Map ||
          fingerprints['primaryLocationLineHash/v1'] is! String) {
        failures.add('sarif smoke case: partialFingerprints missing.');
      }
    }

    // Determinism: encoding twice must yield byte-identical output, otherwise
    // CI baselines will churn for cosmetic reasons.
    final second = writer.encode(report.findings, targetPath: fixturePath);
    if (second != encoded) {
      failures.add('sarif smoke case: output is not deterministic.');
    }
  } catch (error, stack) {
    failures.add('sarif smoke case crashed: $error\n$stack');
  }
}

/// Verifies that `.fshrc.yaml` is actually being applied. The fixture the
/// case points at declares `supabase-signed-url-ttl.severity: low` and
/// `rls-policy-suggestion: off`, so:
///   * the finding must exist with severity LOW (not HIGH),
///   * the suggestion rule must be silent,
///   * the config-level `fail_on: high` must mean the LOW finding does not
///     trigger a non-zero exit under the CLI semantics.
void _runConfigCase(List<String> failures) {
  const path = 'test/fixtures/config_file_app';
  try {
    final config = const ConfigLoader().loadFromRoot(path);
    if (config.isEmpty) {
      failures.add('config_file_app: expected non-empty ScannerConfig.');
      return;
    }
    if (!config.isRuleDisabled('rls-policy-suggestion')) {
      failures.add(
        'config_file_app: `rls-policy-suggestion` should be disabled.',
      );
    }
    if (config.severityFor('supabase-signed-url-ttl') !=
        FindingSeverity.low) {
      failures.add(
        'config_file_app: signed-url-ttl severity override was not read.',
      );
    }
    if (config.failOn != FindingSeverity.high) {
      failures.add(
        'config_file_app: fail_on should parse to FindingSeverity.high.',
      );
    }

    final report = ProjectScanner(
      includeSuggestions: true,
      config: config,
    ).scan(path);

    final signed = report.findings.where(
      (f) => f.code == 'supabase-signed-url-ttl',
    );
    if (signed.isEmpty) {
      failures.add(
        'config_file_app: expected signed-url-ttl finding to still fire.',
      );
    } else if (signed.first.severity != FindingSeverity.low) {
      failures.add(
        'config_file_app: severity override not applied '
        '(got ${signed.first.severity}).',
      );
    }

    final suggestionCount = report.findings
        .where((f) => f.code == 'rls-policy-suggestion')
        .length;
    if (suggestionCount != 0) {
      failures.add(
        'config_file_app: disabled suggestion rule still produced '
        '$suggestionCount finding(s).',
      );
    }

    // Simulate the CLI's exit-code computation with effectiveFailOn=HIGH.
    final hasFail = report.findings
        .where((f) => !f.isSuggestion)
        .any((f) => (f.severity?.sortOrder ?? 3) <= FindingSeverity.high.sortOrder);
    if (hasFail) {
      failures.add(
        'config_file_app: LOW finding should not trip fail_on=high.',
      );
    }
  } catch (error, stack) {
    failures.add('config_file_app: smoke case crashed: $error\n$stack');
  }
}

/// Exercises the baseline round-trip: capture → encode → decode → filter.
///
/// The adoption workflow is: a team with an existing codebase runs the
/// scanner once, writes a baseline, and expects *future* runs against the
/// same code to suppress every finding. We model that flow on a fixture
/// that deliberately produces several findings.
void _runBaselineCase(List<String> failures) {
  const fixturePath = 'test/fixtures/edge_function_secrets_app';
  final tempDir = Directory.systemTemp.createTempSync('fshelper-baseline-');
  try {
    final report = const ProjectScanner(
      includeSuggestions: false,
    ).scan(fixturePath);
    if (report.findings.isEmpty) {
      failures.add(
        'baseline smoke case: fixture produced zero findings, cannot exercise baseline.',
      );
      return;
    }

    final baseline = BaselineFile.fromFindings(
      report.findings,
      toolVersion: SarifWriter.kToolVersion,
    );
    final encoded = baseline.encode();

    // Encoded baseline must parse as JSON with the expected shape.
    final decoded = jsonDecode(encoded);
    if (decoded is! Map) {
      failures.add('baseline smoke case: encoded baseline is not an object.');
      return;
    }
    if (decoded['schema_version'] != 1) {
      failures.add(
        'baseline smoke case: schema_version is ${decoded['schema_version']}, expected 1.',
      );
    }
    final rawEntries = decoded['fingerprints'];
    if (rawEntries is! List || rawEntries.length != report.findings.length) {
      failures.add(
        'baseline smoke case: fingerprints count mismatch '
        '(${(rawEntries is List) ? rawEntries.length : "not a list"} vs ${report.findings.length}).',
      );
    }

    // Write + read round-trip.
    final baselineFile = File('${tempDir.path}/.fsbaseline.json');
    baseline.writeToFile(baselineFile.path);
    final reloaded = BaselineFile.loadFromFile(baselineFile.path);
    if (reloaded.entries.length != report.findings.length) {
      failures.add(
        'baseline smoke case: reloaded entries count is '
        '${reloaded.entries.length} (expected ${report.findings.length}).',
      );
    }

    // Filtering: every finding in the current report must be suppressed
    // because the baseline was built from exactly this list.
    final filtered = reloaded.filter(report.findings);
    if (filtered.isNotEmpty) {
      failures.add(
        'baseline smoke case: expected all findings to be suppressed, '
        'but ${filtered.length} survived.',
      );
    }

    // A synthetic "new" finding (different message) must pass through the
    // filter — baseline suppression must be opt-in per fingerprint.
    final synthetic = Finding(
      severity: FindingSeverity.high,
      confidence: FindingConfidence.high,
      category: FindingCategory.security,
      code: 'supabase-edge-function-secrets',
      message: 'Synthetic new finding — not in baseline',
      fix: 'n/a',
      filePath: 'supabase/functions/hello/index.ts',
      line: 999,
    );
    final withSynthetic = reloaded.filter(<Finding>[...report.findings, synthetic]);
    if (withSynthetic.length != 1 || withSynthetic.first.message != synthetic.message) {
      failures.add(
        'baseline smoke case: synthetic new finding should pass through, '
        'got ${withSynthetic.map((f) => f.message).toList()}.',
      );
    }

    // Fingerprint determinism: encoding twice must yield the same result so
    // the baseline file does not churn in git.
    final secondEncoded = BaselineFile.fromFindings(
      report.findings,
      toolVersion: SarifWriter.kToolVersion,
      now: DateTime.utc(2026, 4, 15),
    ).encode();
    final thirdEncoded = BaselineFile.fromFindings(
      report.findings,
      toolVersion: SarifWriter.kToolVersion,
      now: DateTime.utc(2026, 4, 15),
    ).encode();
    if (secondEncoded != thirdEncoded) {
      failures.add(
        'baseline smoke case: encoded baseline is not deterministic for the '
        'same inputs.',
      );
    }
  } catch (error, stack) {
    failures.add('baseline smoke case crashed: $error\n$stack');
  } finally {
    if (tempDir.existsSync()) {
      tempDir.deleteSync(recursive: true);
    }
  }
}

void _runMalformedEncodingCase(List<String> failures) {
  final tempRoot = Directory.systemTemp.createTempSync('fshelper-malformed-');
  try {
    Directory('${tempRoot.path}/lib').createSync(recursive: true);
    File(
      '${tempRoot.path}/pubspec.yaml',
    ).writeAsStringSync('name: malformed_encoding_app\n');
    File(
      '${tempRoot.path}/lib/main.dart',
    ).writeAsStringSync('void main() {}\n');
    File(
      '${tempRoot.path}/README.md',
    ).writeAsBytesSync([0xff, 0xfe, 0x00, 0x61]);

    try {
      final report = const ProjectScanner(
        includeSuggestions: false,
      ).scan(tempRoot.path);
      final issueCount = report.findings
          .where((finding) => !finding.isSuggestion)
          .length;
      if (issueCount != 0) {
        failures.add(
          'malformed_encoding_app should not crash or produce issues, but found $issueCount issue(s).',
        );
      }
    } catch (error) {
      failures.add('malformed_encoding_app crashed: $error');
    }
  } finally {
    if (tempRoot.existsSync()) {
      tempRoot.deleteSync(recursive: true);
    }
  }
}
