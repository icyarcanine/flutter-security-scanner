import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

Future<void> main() async {
  await dotenv.load();
  await Supabase.initialize(
    url: dotenv.env['SUPABASE_URL']!,
    anonKey: dotenv.env['SUPABASE_ANON_KEY']!,
  );

  final storage = Supabase.instance.client.storage.from('user-media');
  // Normally fires supabase-signed-url-ttl (HIGH — 1 year), but the
  // .fshrc.yaml downgrades this rule's severity to low.
  await storage.createSignedUrl('exports/report.csv', 31536000);
}
