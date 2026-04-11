"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildDefaultRules = buildDefaultRules;
const hardcodedSecretsRule_1 = require("./security/hardcodedSecretsRule");
const committedEnvRule_1 = require("./security/committedEnvRule");
const sensitiveLoggingRule_1 = require("./security/sensitiveLoggingRule");
const clientSideTrustRule_1 = require("./security/clientSideTrustRule");
const fileUploadValidationRule_1 = require("./security/fileUploadValidationRule");
const publicStorageRule_1 = require("./security/publicStorageRule");
const debugCodeRule_1 = require("./config/debugCodeRule");
const environmentVariablesRule_1 = require("./config/environmentVariablesRule");
const invalidSupabaseUrlRule_1 = require("./config/invalidSupabaseUrlRule");
const multipleSupabaseClientsRule_1 = require("./config/multipleSupabaseClientsRule");
const improperInitializationRule_1 = require("./config/improperInitializationRule");
const placeholderEnvValuesRule_1 = require("./config/placeholderEnvValuesRule");
const missingRlsAwarenessRule_1 = require("./supabase/missingRlsAwarenessRule");
const rlsPolicySuggestionRule_1 = require("./supabase/rlsPolicySuggestionRule");
const tableOwnershipRule_1 = require("./supabase/tableOwnershipRule");
function buildDefaultRules(includeSuggestions) {
    const rules = [
        // Security
        new hardcodedSecretsRule_1.HardcodedSecretsRule(),
        new committedEnvRule_1.CommittedEnvRule(),
        new sensitiveLoggingRule_1.SensitiveLoggingRule(),
        new clientSideTrustRule_1.ClientSideTrustRule(),
        new fileUploadValidationRule_1.FileUploadValidationRule(),
        new publicStorageRule_1.PublicStorageRule(),
        // Config
        new environmentVariablesRule_1.EnvironmentVariablesRule(),
        new placeholderEnvValuesRule_1.PlaceholderEnvValuesRule(),
        new invalidSupabaseUrlRule_1.InvalidSupabaseUrlRule(),
        new multipleSupabaseClientsRule_1.MultipleSupabaseClientsRule(),
        new improperInitializationRule_1.ImproperInitializationRule(),
        new debugCodeRule_1.DebugCodeRule(),
        // Supabase / RLS
        new missingRlsAwarenessRule_1.MissingRlsAwarenessRule(),
        new tableOwnershipRule_1.TableOwnershipRule(),
    ];
    if (includeSuggestions) {
        rules.push(new rlsPolicySuggestionRule_1.RlsPolicySuggestionRule());
    }
    return rules;
}
