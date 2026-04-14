import 'package:shared_preferences/shared_preferences.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

Future<void> saveToken(String jwt) async {
  final prefs = await SharedPreferences.getInstance();
  prefs.setString('token', jwt);
}
