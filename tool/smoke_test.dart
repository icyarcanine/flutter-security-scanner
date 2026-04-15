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

  _runMalformedEncodingCase(failures);

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
  final report = ProjectScanner(
    includeSuggestions: includeSuggestions,
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
