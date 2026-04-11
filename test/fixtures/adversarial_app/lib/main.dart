import 'package:supabase_flutter/supabase_flutter.dart';

void main() {
  final tokenCount = 5;
  final userName = 'Test';
  final sessionLength = 3600;
  final tokenize = true;
  final userData = {};

  // Must NOT trigger sensitive logging
  print(tokenCount);
  print(userName);
  print(sessionLength);
  print(tokenize);
  print(userData);

  // Must trigger sensitive logging
  final session = '123';
  final accessToken = 'abc';
  print(session);
  print(accessToken);

  // Multi-line logging must trigger sensitive logging
  print(
    accessToken
  );

  // Storage safe upload must not be HIGH
  final userId = '123';
  final supabase = Supabase.instance.client;
  // public bucket but path does not have userId
  supabase.storage.from('public').upload('temp/log.txt', []);
  // private bucket, has userId (must NOT be HIGH)
  supabase.storage.from('private_docs').upload('temp/$userId/log.txt', []);
  // public bucket, safe context not matching "avatar, profile, user, private"
  supabase.storage.from('public').upload('temp/$userId/log.txt', []); // Wait, the rule says: REQUIRE BOTH user identifier AND sensitive context.
}
