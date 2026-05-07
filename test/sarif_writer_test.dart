import 'dart:convert';

import 'package:fluttersupabasehelper/fluttersupabasehelper.dart';
import 'package:test/test.dart';

/// §IN-2 — every result physicalLocation must carry `region.snippet.text` and
/// `contextRegion.snippet.text` whenever the file is in the corpus. The two
/// fields together let SARIF viewers (notably GitHub Code Scanning) render
/// the offending line plus surrounding context inline.
void main() {
  group('SarifWriter snippet embedding (§IN-2)', () {
    test('embeds region.snippet and contextRegion when fileLines is supplied', () {
      const filePath = 'lib/example.dart';
      final lines = <String>[
        'void start() {',
        '  print("hello");',
        '  var key = "AKIAIOSFODNN7REALKEY";',
        '  print(key);',
        '}',
      ];
      final finding = Finding(
        code: 'generic-secret',
        message: 'AWS access key in source',
        risk: 'Hardcoded credential',
        fix: 'Move to environment',
        category: FindingCategory.security,
        severity: FindingSeverity.high,
        confidence: FindingConfidence.high,
        filePath: filePath,
        line: 3,
      );

      const writer = SarifWriter();
      final json = writer.encode(
        [finding],
        targetPath: '/repo',
        fileLines: {filePath: lines},
      );
      final decoded = jsonDecode(json) as Map<String, Object?>;
      final results =
          ((decoded['runs'] as List).first as Map)['results'] as List;
      expect(results, hasLength(1));

      final loc = ((results.first as Map)['locations'] as List).first as Map;
      final phys = loc['physicalLocation'] as Map;
      final region = phys['region'] as Map;
      final snippet = region['snippet'] as Map;
      expect(snippet['text'], '  var key = "AKIAIOSFODNN7REALKEY";');

      final ctx = phys['contextRegion'] as Map;
      expect(ctx['startLine'], 1);
      expect(ctx['endLine'], 5);
      final ctxText = (ctx['snippet'] as Map)['text'] as String;
      expect(ctxText.split('\n').length, 5);
      expect(ctxText.contains('void start()'), isTrue);
      expect(ctxText.contains('var key'), isTrue);
    });

    test('omits snippet/contextRegion when no fileLines passed', () {
      final finding = Finding(
        code: 'generic-secret',
        message: 'msg',
        risk: 'risk',
        fix: 'fix',
        category: FindingCategory.security,
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.high,
        filePath: 'main.dart',
        line: 1,
      );
      const writer = SarifWriter();
      final json = writer.encode([finding], targetPath: '/repo');
      final decoded = jsonDecode(json) as Map<String, Object?>;
      final results =
          ((decoded['runs'] as List).first as Map)['results'] as List;
      final phys =
          (((results.first as Map)['locations'] as List).first as Map)['physicalLocation']
              as Map;
      final region = phys['region'] as Map;
      expect(region.containsKey('snippet'), isFalse);
      expect(phys.containsKey('contextRegion'), isFalse);
    });

    test('clamps absurdly long lines so SARIF stays compact', () {
      final hugeLine = 'x' * (SarifWriter.kMaxSnippetLineChars + 200);
      final finding = Finding(
        code: 'generic-secret',
        message: 'msg',
        risk: 'risk',
        fix: 'fix',
        category: FindingCategory.security,
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.high,
        filePath: 'big.js',
        line: 1,
      );
      const writer = SarifWriter();
      final json = writer.encode(
        [finding],
        fileLines: {'big.js': [hugeLine]},
      );
      final decoded = jsonDecode(json) as Map<String, Object?>;
      final results =
          ((decoded['runs'] as List).first as Map)['results'] as List;
      final phys =
          (((results.first as Map)['locations'] as List).first as Map)['physicalLocation']
              as Map;
      final region = phys['region'] as Map;
      final snippet = (region['snippet'] as Map)['text'] as String;
      expect(snippet.length, lessThanOrEqualTo(SarifWriter.kMaxSnippetLineChars + 1));
      expect(snippet.endsWith('…'), isTrue);
    });
  });
}
