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
import { RustEngineTaintRule } from './security/rustEngineTaintRule';
import { InsecureRandomRule } from './security/insecureRandomRule';
import { JwtMisuseRule } from './security/jwtMisuseRule';
import { InsecureCookieRule } from './security/insecureCookieRule';
import { CorsMisconfigRule } from './security/corsMisconfigRule';
import { HardcodedIpRule } from './security/hardcodedIpRule';
import { ImproperCertValidationRule } from './security/improperCertValidationRule';
import { TabnabbingRule } from './security/tabnabbingRule';
import { CleartextHttpRule } from './security/cleartextHttpRule';
import { WeakCryptoJsRule } from './security/weakCryptoJsRule';
import { InsecureWebStorageRule } from './security/insecureWebStorageRule';
import { ErrorInfoDisclosureRule } from './security/errorInfoDisclosureRule';
import { ClipboardExposureRule } from './security/clipboardExposureRule';
import { PathTraversalJsRule } from './security/pathTraversalJsRule';
import { DependencyConfusionRule } from './security/dependencyConfusionRule';
import { SymlinkFollowingRule } from './security/symlinkFollowingRule';
import { SecureStorageLoggingRule } from './security/secureStorageLoggingRule';
import { AndroidWebViewJsInterfaceRule } from './security/androidWebViewJsInterfaceRule';
import { PythonFormatInjectionRule } from './security/pythonFormatInjectionRule';
import { PrototypePollutionRule } from './security/prototypePollutionRule';
import { RedosRule } from './security/redosRule';
import { UnscopedRealtimeChannelRule } from './supabase/unscopedRealtimeChannelRule';
import { RealtimeSubscriptionLeakRule } from './supabase/realtimeSubscriptionLeakRule';

export function buildDefaultRules(includeSuggestions: boolean): Rule[] {
  const rules: Rule[] = [
    // SAST High-Priority
    new GenericSecretRule(),
    new InjectionRule(),
    new XssRule(),
    new UnsafeEvalRule(),
    new RustEngineTaintRule(),
    new InsecureRandomRule(),
    new JwtMisuseRule(),
    new InsecureCookieRule(),
    new CorsMisconfigRule(),
    new HardcodedIpRule(),
    new ImproperCertValidationRule(),
    new TabnabbingRule(),
    new CleartextHttpRule(),
    new WeakCryptoJsRule(),
    new InsecureWebStorageRule(),
    new ErrorInfoDisclosureRule(),
    new ClipboardExposureRule(),
    new PathTraversalJsRule(),
    new DependencyConfusionRule(),
    new SymlinkFollowingRule(),
    new SecureStorageLoggingRule(),
    new AndroidWebViewJsInterfaceRule(),
    new PythonFormatInjectionRule(),
    new PrototypePollutionRule(),
    new RedosRule(),
    new UnscopedRealtimeChannelRule(),
    new RealtimeSubscriptionLeakRule(),

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
