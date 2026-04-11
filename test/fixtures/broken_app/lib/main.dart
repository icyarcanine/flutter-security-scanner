import 'package:supabase_flutter/supabase_flutter.dart';

Future<void> main() async {
  final userId = 'route-user-id';

  await Supabase.initialize(
    url: 'https://demo-project.supabase.co',
    anonKey: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature',
  );

  final session = Supabase.instance.client.auth.currentSession;
  print(session);
  print('debug mode');

  final supabase = Supabase.instance.client;
  final anotherClient = SupabaseClient(
    'https://second-project.supabase.co',
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature',
  );
  final thirdClient = SupabaseClient(
    'https://third-project.supabase.co',
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature',
  );

  await supabase.from('posts').select();
  await supabase.from('profiles').update({'display_name': 'Icy'});
  await supabase.from('posts').select().eq('user_id', userId);
  await supabase.storage.from('public').upload('avatars/$userId.png', userId);

  print(anotherClient);
  print(thirdClient);
}
