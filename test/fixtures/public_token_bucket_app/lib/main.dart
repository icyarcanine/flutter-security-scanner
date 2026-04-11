import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

Future<void> main() async {
  await dotenv.load();
  await Supabase.initialize(
    url: dotenv.env['SUPABASE_URL']!,
    anonKey: dotenv.env['SUPABASE_ANON_KEY']!,
  );

  const allowedExtensions = ['.txt'];
  const maxFileSize = 10;
  final fileSize = 4;
  if (!allowedExtensions.contains('.txt') || fileSize > maxFileSize) {
    return;
  }

  await Supabase.instance.client.storage
      .from('republications')
      .upload('notes/x.txt', 'x');
}
