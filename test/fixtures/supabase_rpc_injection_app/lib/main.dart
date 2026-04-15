import 'package:supabase_flutter/supabase_flutter.dart';

Future<void> run(String userFunc, String userEmail) async {
  final supabase = Supabase.instance.client;

  // HIGH — string interpolation in the RPC function name.
  await supabase.rpc('call_$userFunc');

  // MEDIUM — raw identifier passed as the RPC function name.
  await supabase.rpc(userFunc);

  // Safe — hardcoded literal. Must not fire.
  await supabase.rpc('fetch_profile');

  // HIGH — `.or()` built with interpolation.
  await supabase
      .from('profiles')
      .select()
      .or('email.eq.$userEmail,username.eq.$userEmail');

  // Safe — parameterised `.eq()`. Must not fire.
  await supabase.from('profiles').select().eq('email', userEmail);
}
