import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';

class PublicStorageRule extends Rule {
  const PublicStorageRule();

  static const _highRiskBuckets = {'public'};
  static const _reviewBuckets = {'avatar', 'avatars', 'public-files'};

  @override
  String get code => 'public-storage';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    for (final bucket in context.storageBucketUses) {
      final normalized = bucket.bucketName.toLowerCase();
      final bucketTokens = normalized.split(RegExp(r'[-_.]+'));
      final looksPublicish =
          _highRiskBuckets.contains(normalized) ||
          _reviewBuckets.contains(normalized) ||
          bucketTokens.contains('public');

      if (!looksPublicish) {
        continue;
      }

      // We MUST require BOTH conditions for HIGH severity:
      // 1. user identifier present ($userId, user.id, uid)
      // 2. sensitive context (avatar, profile, user, private)
      final isHighRisk =
          bucket.pathHasUserIdPattern && bucket.pathHasSensitiveContext;

      if (!isHighRisk) {
        continue; // Downgrade by ignoring (zero false positive principle)
      }

      final severity = FindingSeverity.high;
      final confidence = FindingConfidence.high;

      findings.add(
        Finding(
          severity: severity,
          confidence: confidence,
          category: FindingCategory.security,
          code: code,
          message:
              "Potentially public storage bucket '${bucket.bucketName}' is used for app data",
          fix:
              'Verify that the bucket should be public. If the files are user-private, switch to a private bucket and enforce access with storage policies.',
          risk:
              'Uploading user-specific files to a public bucket allows anyone to read those files if they can guess the URL.',
          filePath: bucket.file.relativePath,
          line: bucket.line,
        ),
      );
    }

    return findings;
  }
}
