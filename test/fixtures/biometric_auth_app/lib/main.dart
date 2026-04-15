import 'package:local_auth/local_auth.dart';

class BiometricGate {
  final LocalAuthentication auth = LocalAuthentication();

  /// Bad #1: default options — PIN fallback enabled, stickyAuth off.
  Future<bool> unlockAccount() async {
    return auth.authenticate(
      localizedReason: 'Please authenticate to view your balance',
    );
  }

  /// Bad #2: biometricOnly present but stickyAuth missing.
  Future<bool> confirmPayment() async {
    return auth.authenticate(
      localizedReason: 'Authorize the payment',
      options: const AuthenticationOptions(biometricOnly: true),
    );
  }

  /// Bad #3: reads canCheckBiometrics as if it were the auth result.
  Future<bool> readSecretDrawer() async {
    final available = await auth.canCheckBiometrics;
    return available; // never calls authenticate() at all
  }
}
