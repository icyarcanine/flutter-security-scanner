import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

Future<void> main() async {
  await dotenv.load();

  await Supabase.initialize(
    url: dotenv.env['SUPABASE_URL']!,
    anonKey: dotenv.env['SUPABASE_ANON_KEY']!,
  );

  final supabase = Supabase.instance.client;
  final currentUser = supabase.auth.currentUser;
  if (currentUser == null) {
    return;
  }

  await supabase.from('posts').select().eq('user_id', currentUser.id);
  const allowedExtensions = ['.txt'];
  const maxSize = 20;
  final fileSize = currentUser.id.length;
  if (!allowedExtensions.contains('.txt') || fileSize > maxSize) {
    return;
  }
  await supabase.storage
      .from('user-media')
      .upload('posts/${currentUser.id}.txt', currentUser.id);
}
