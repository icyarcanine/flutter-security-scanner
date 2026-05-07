import 'package:local_auth/local_auth.dart';

class GoodBiometricGate {
  final LocalAuthentication auth = LocalAuthentication();

  Future<bool> unlockAccount() async {
    return auth.authenticate(
      localizedReason: 'Please authenticate to view your balance',
      options: const AuthenticationOptions(
        biometricOnly: true,
        stickyAuth: true,
      ),
    );
  }
}
