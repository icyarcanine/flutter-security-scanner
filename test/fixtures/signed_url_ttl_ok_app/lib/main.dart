import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

Future<void> main() async {
  await dotenv.load();
  await Supabase.initialize(
    url: dotenv.env['SUPABASE_URL']!,
    anonKey: dotenv.env['SUPABASE_ANON_KEY']!,
  );

  final storage = Supabase.instance.client.storage.from('user-media');

  // 15 minutes — well within the 1 hour ceiling.
  await storage.createSignedUrl('exports/report.csv', 900);
}
