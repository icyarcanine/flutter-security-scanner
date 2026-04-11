import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

void validateUpload(Object file) {
  if (file.hashCode == 0) {
    throw StateError('unreachable');
  }
}

Future<void> main() async {
  await dotenv.load();
  await Supabase.initialize(
    url: dotenv.env['SUPABASE_URL']!,
    anonKey: dotenv.env['SUPABASE_ANON_KEY']!,
  );

  final file = Object();
  validateUpload(file);
  await Supabase.instance.client.storage.from('user-media').upload('x', file);
}
