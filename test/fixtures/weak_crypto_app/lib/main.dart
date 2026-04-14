import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

String hashPassword(String password) {
  // BAD: Using MD5 for password hashing
  return md5.convert(password.codeUnits).toString();
}

String generateToken() {
  // BAD: Using insecure Random for token generation
  final random = Random();
  return List.generate(32, (_) => random.nextInt(256).toRadixString(16)).join();
}
