import 'rule.dart';
import 'rules/config/debug_code_rule.dart';
import 'rules/config/environment_variables_rule.dart';
import 'rules/config/improper_initialization_rule.dart';
import 'rules/config/invalid_supabase_url_rule.dart';
import 'rules/config/multiple_supabase_clients_rule.dart';
import 'rules/config/placeholder_env_values_rule.dart';
import 'rules/security/client_side_trust_rule.dart';
import 'rules/security/committed_env_rule.dart';
import 'rules/security/file_upload_validation_rule.dart';
import 'rules/security/certificate_pinning_rule.dart';
import 'rules/security/clipboard_exposure_rule.dart';
import 'rules/security/deep_link_validation_rule.dart';
import 'rules/security/generic_secret_rule.dart';
import 'rules/security/gradle_secrets_rule.dart';
import 'rules/security/hardcoded_secrets_rule.dart';
import 'rules/security/injection_rule.dart';
import 'rules/security/insecure_deserialization_rule.dart';
import 'rules/security/insecure_storage_rule.dart';
import 'rules/security/path_traversal_rule.dart';
import 'rules/security/plaintext_http_rule.dart';
import 'rules/security/platform_security_rule.dart';
import 'rules/security/public_storage_rule.dart';
import 'rules/security/sensitive_logging_rule.dart';
import 'rules/security/unobscured_password_rule.dart';
import 'rules/security/unsafe_eval_rule.dart';
import 'rules/security/weak_crypto_rule.dart';
import 'rules/security/webview_security_rule.dart';
import 'rules/security/xss_rule.dart';
import 'rules/supabase/missing_rls_awareness_rule.dart';
import 'rules/supabase/rls_policy_suggestion_rule.dart';
import 'rules/supabase/table_ownership_rule.dart';

List<Rule> buildDefaultRules({required bool includeSuggestions}) {
  final rules = <Rule>[
    // SAST High-Priority
    const GenericSecretRule(),
    const InjectionRule(),
    const XssRule(),
    const UnsafeEvalRule(),
    // Security
    const HardcodedSecretsRule(),
    const CommittedEnvRule(),
    const SensitiveLoggingRule(),
    const ClientSideTrustRule(),
    const FileUploadValidationRule(),
    const PublicStorageRule(),
    const InsecureStorageRule(),
    const PlaintextHttpRule(),
    const WebViewSecurityRule(),
    const CertificatePinningRule(),
    const DeepLinkValidationRule(),
    const PlatformSecurityRule(),
    const WeakCryptoRule(),
    const ClipboardExposureRule(),
    const InsecureDeserializationRule(),
    const PathTraversalRule(),
    const UnobscuredPasswordRule(),
    const GradleSecretsRule(),
    // Config
    const EnvironmentVariablesRule(),
    const PlaceholderEnvValuesRule(),
    const InvalidSupabaseUrlRule(),
    const MultipleSupabaseClientsRule(),
    const ImproperInitializationRule(),
    const DebugCodeRule(),
    // Supabase / RLS
    const MissingRlsAwarenessRule(),
    const TableOwnershipRule(),
  ];

  if (includeSuggestions) {
    rules.add(const RlsPolicySuggestionRule());
  }

  return rules;
}
