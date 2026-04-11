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
import 'rules/security/hardcoded_secrets_rule.dart';
import 'rules/security/public_storage_rule.dart';
import 'rules/security/sensitive_logging_rule.dart';
import 'rules/supabase/missing_rls_awareness_rule.dart';
import 'rules/supabase/rls_policy_suggestion_rule.dart';
import 'rules/supabase/table_ownership_rule.dart';

List<Rule> buildDefaultRules({required bool includeSuggestions}) {
  final rules = <Rule>[
    // Security
    const HardcodedSecretsRule(),
    const CommittedEnvRule(),
    const SensitiveLoggingRule(),
    const ClientSideTrustRule(),
    const FileUploadValidationRule(),
    const PublicStorageRule(),
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
