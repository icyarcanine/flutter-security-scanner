import 'package:flutter/material.dart';
import 'package:supabase_flutter/supabase_flutter.dart';
import 'package:logging/logging.dart';

final _logger = Logger('DataScreen');

Future<void> main() async {
  await Supabase.initialize(
    url: const String.fromEnvironment('SUPABASE_URL'),
    anonKey: const String.fromEnvironment('SUPABASE_ANON_KEY'),
  );
  runApp(MaterialApp(home: DataScreen()));
}

class DataScreen extends StatelessWidget {
  Future<void> saveData(BuildContext context) async {
    try {
      await Supabase.instance.client
          .from('users')
          .insert({'name': 'Test'});
    } catch (error) {
      // Log full error internally
      _logger.severe('Database insert failed', error);
      // Show generic, sanitized message to user
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Unable to save data. Please try again.')),
      );
    }
  }

  Future<void> login(String email, String password) async {
    // Rate limit: prevent brute-force
    await Future.delayed(Duration(seconds: 1));
    try {
      await Supabase.instance.client.auth.signInWithPassword(
        email: email,
        password: password,
      );
    } on AuthException {
      // Generic error — does not reveal user existence
      throw Exception('Invalid credentials');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container();
  }
}
