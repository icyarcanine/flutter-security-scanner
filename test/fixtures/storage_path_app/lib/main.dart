import 'package:supabase_flutter/supabase_flutter.dart';

void main() {
  final supabase = Supabase.instance.client;
  final userId = '123';

  // This uses a "public" looking bucket AND the path has $userId.
  // It should trigger public-storage with HIGH severity.
  supabase.storage
      .from('public_avatars')
      .upload('profiles/$userId/avatar.png', []);
}
