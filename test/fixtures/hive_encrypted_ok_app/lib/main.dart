import 'package:hive/hive.dart';

Future<Box> openEncrypted(List<int> key) async {
  return Hive.openBox(
    'profile',
    encryptionCipher: HiveAesCipher(key),
  );
}
