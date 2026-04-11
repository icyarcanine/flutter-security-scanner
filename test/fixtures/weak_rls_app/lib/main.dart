import 'package:supabase_flutter/supabase_flutter.dart';

void main() {
  final supabase = Supabase.instance.client;
  // This triggers a table access, which usually triggers missing-rls-awareness with HIGH severity
  supabase.from('posts').select();

  // A casual mention of row level security to downgrade it to WEAK
  // "Row level security will be added later"
}
