import 'package:supabase_flutter/supabase_flutter.dart';

// DANGER: this is the exact mistake the rule is built to catch. A real
// `service_role` JWT (payload `{"role":"service_role"}`) baked into the
// Flutter client gives every attacker full database access.
const _supabaseServiceRoleKey =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6OTk5OTk5OTk5OX0.ZmFrZS1zaWduYXR1cmUtbm90LXJlYWwtanVzdC1zaGFwZQ';

// Safe counterpart — the anon key. Should NOT trigger this rule.
const _supabaseAnonKey =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjk5OTk5OTk5OTl9.ZmFrZS1zaWduYXR1cmUtbm90LXJlYWwtanVzdC1zaGFwZQ';

Future<void> main() async {
  await Supabase.initialize(
    url: 'https://example.supabase.co',
    anonKey: _supabaseServiceRoleKey, // <-- deliberately wrong
  );
  print('anon key len: ${_supabaseAnonKey.length}');
}
