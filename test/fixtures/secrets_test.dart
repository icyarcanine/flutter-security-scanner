class SecretTests {
  // Scenario 1: Vulnerable - AWS Key (Expected: Catch)
  final awsKey = "AKIAIOSFODNN7REALKEY";

  // Scenario 2: Vulnerable - Generic Secret Token (Expected: Catch)
  final token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";

  // Scenario 3: Safe - Environment Variable (Expected: Safe)
  final envToken = const String.fromEnvironment('API_KEY');

  // Scenario 4: Blindspot - Split String Obfuscation (Expected: Miss)
  final splitKey = "AKIA" + "IOSF" + "ODNN7" + "REALKEY";

  // Scenario 5: Vulnerable - Firebase Key (Expected: Catch)
  final firebaseKey = "AIzaSyC_REALKEYREALKEYREALKEYREAL123456";

  // Scenario 6: False Positive - High entropy random string that isn't a secret (Expected: Catch - FP)
  final hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
}
