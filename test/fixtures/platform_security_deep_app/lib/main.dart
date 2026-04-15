import 'package:encrypt/encrypt.dart';

// Native crypto usage — this drives the ITSAppUsesNonExemptEncryption
// mismatch branch in the iOS plist check.
void main() {
  final key = Key.fromUtf8('0123456789abcdef0123456789abcdef');
  final iv = IV.fromLength(16);
  final encrypter = Encrypter(AES(key));
  encrypter.encrypt('hello', iv: iv);
}
