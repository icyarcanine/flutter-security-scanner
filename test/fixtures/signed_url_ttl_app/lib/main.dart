import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

Future<void> main() async {
  await dotenv.load();
  await Supabase.initialize(
    url: dotenv.env['SUPABASE_URL']!,
    anonKey: dotenv.env['SUPABASE_ANON_KEY']!,
  );

  final storage = Supabase.instance.client.storage.from('user-media');

  // HIGH — 1 year TTL. This is basically a public link.
  await storage.createSignedUrl('exports/report.csv', 31536000);

  // MEDIUM — 6 hour TTL via Duration constant.
  await storage.createSignedUrl(
    'exports/nightly.csv',
    Duration(hours: 6).inSeconds,
  );

  // LOW — dynamic TTL from a variable.
  final kTtl = 7200;
  await storage.createSignedUrl('exports/intraday.csv', kTtl);
}
