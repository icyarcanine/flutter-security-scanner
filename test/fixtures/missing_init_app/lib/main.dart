import 'package:supabase_flutter/supabase_flutter.dart';

void main() {
  final client = Supabase.instance.client;
  client.auth.currentUser;
}
