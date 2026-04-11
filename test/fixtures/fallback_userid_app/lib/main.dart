import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

Future<void> main() async {
  await dotenv.load();
  await Supabase.initialize(
    url: dotenv.env['SUPABASE_URL']!,
    anonKey: dotenv.env['SUPABASE_ANON_KEY']!,
  );

  final suppliedUserId = 'route-value';
  final currentUser = Supabase.instance.client.auth.currentUser;
  await Supabase.instance.client
      .from('posts')
      .select()
      .eq('user_id', currentUser?.id ?? suppliedUserId);
}
