import { Rule } from './rule';
import { HardcodedSecretsRule } from './security/hardcodedSecretsRule';
import { CommittedEnvRule } from './security/committedEnvRule';
import { SensitiveLoggingRule } from './security/sensitiveLoggingRule';
import { ClientSideTrustRule } from './security/clientSideTrustRule';
import { FileUploadValidationRule } from './security/fileUploadValidationRule';
import { PublicStorageRule } from './security/publicStorageRule';
import { DebugCodeRule } from './config/debugCodeRule';
import { EnvironmentVariablesRule } from './config/environmentVariablesRule';
import { InvalidSupabaseUrlRule } from './config/invalidSupabaseUrlRule';
import { MultipleSupabaseClientsRule } from './config/multipleSupabaseClientsRule';
import { ImproperInitializationRule } from './config/improperInitializationRule';
import { PlaceholderEnvValuesRule } from './config/placeholderEnvValuesRule';
import { MissingRlsAwarenessRule } from './supabase/missingRlsAwarenessRule';
import { RlsPolicySuggestionRule } from './supabase/rlsPolicySuggestionRule';
import { TableOwnershipRule } from './supabase/tableOwnershipRule';

// New SAST Rules
import { GenericSecretRule } from './secrets/genericSecretRule';
import { InjectionRule } from './security/injectionRule';
import { XssRule } from './security/xssRule';
import { UnsafeEvalRule } from './bugs/unsafeEvalRule';
import { IfdsTaintRule } from './security/ifdsTaintRule';

export function buildDefaultRules(includeSuggestions: boolean): Rule[] {
  const rules: Rule[] = [
    // SAST High-Priority
    new GenericSecretRule(),
    new InjectionRule(),
    new XssRule(),
    new UnsafeEvalRule(),
    new IfdsTaintRule(),

    // Security
    new HardcodedSecretsRule(),
    new CommittedEnvRule(),
    new SensitiveLoggingRule(),
    new ClientSideTrustRule(),
    new FileUploadValidationRule(),
    new PublicStorageRule(),
    // Config
    new EnvironmentVariablesRule(),
    new PlaceholderEnvValuesRule(),
    new InvalidSupabaseUrlRule(),
    new MultipleSupabaseClientsRule(),
    new ImproperInitializationRule(),
    new DebugCodeRule(),
    // Supabase / RLS
    new MissingRlsAwarenessRule(),
    new TableOwnershipRule(),
  ];

  if (includeSuggestions) {
    rules.push(new RlsPolicySuggestionRule());
  }

  return rules;
}
