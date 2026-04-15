import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

Future<void> main() async {
  await dotenv.load();
  await Supabase.initialize(
    url: dotenv.env['SUPABASE_URL']!,
    anonKey: dotenv.env['SUPABASE_ANON_KEY']!,
  );

  final uid = Supabase.instance.client.auth.currentUser!.id;

  Supabase.instance.client
      .channel('public:messages:$uid')
      .onPostgresChanges(
        event: PostgresChangeEvent.all,
        schema: 'public',
        table: 'messages',
        filter: 'receiver_id=eq.$uid',
        callback: _noop,
      )
      .subscribe();
}

void _noop(PostgresChangePayload payload) {}
