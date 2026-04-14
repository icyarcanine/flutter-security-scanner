import 'package:supabase_flutter/supabase_flutter.dart';

void main() {
  final session = Supabase.instance.client.auth.currentSession;

  // This should be flagged by SensitiveLoggingRule
  print(
    'User session is: '
    '\${session?.accessToken}',
  );

  // This should be flagged by DebugCodeRule, NOT SensitiveLoggingRule
  print(
    'Just some '
    'harmless '
    'debug info',
  );
}
