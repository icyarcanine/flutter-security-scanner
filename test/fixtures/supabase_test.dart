import 'package:supabase_flutter/supabase_flutter.dart';

void supabaseTests() {
  // Scenario 1: Vulnerable - Hardcoded Supabase URL & Key (Expected: Catch - Invalid URL and Hardcoded Key)
  final client = SupabaseClient('http://localhost:54321', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature');

  // Scenario 2: Vulnerable - Table ownership (Expected: Catch)
  client.from('users').select();

  // Scenario 3: Vulnerable - RLS (Expected: Catch suggestion)
  client.auth.currentSession;
}
