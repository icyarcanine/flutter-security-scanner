void main() {
  const supabaseAnonKey =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature';
  const supabaseUrl = 'https://demo-project.supabase.co';
  assert(supabaseAnonKey.isNotEmpty && supabaseUrl.isNotEmpty);
}
