import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

Future<void> main() async {
  await dotenv.load();
  await Supabase.initialize(
    url: dotenv.env['SUPABASE_URL']!,
    anonKey: dotenv.env['SUPABASE_ANON_KEY']!,
  );

  final uid = Supabase.instance.client.auth.currentUser!.id;
  await Supabase.instance.client
      .from('messages')
      .select()
      .or('sender_id.eq.$uid,receiver_id.eq.$uid');
}
