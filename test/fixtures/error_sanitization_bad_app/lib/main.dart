import 'package:flutter/material.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

class DataScreen extends StatelessWidget {
  Future<void> saveData(BuildContext context) async {
    try {
      await Supabase.instance.client
          .from('users')
          .insert({'name': 'Test'});
    } catch (error) {
      // Raw error exposed directly to user UI
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(error.toString())),
      );
    }
  }

  Future<void> login(String email, String password) async {
    try {
      await Supabase.instance.client.auth.signInWithPassword(
        email: email,
        password: password,
      );
    } on AuthException catch (error) {
      // Specific error messages reveal user existence
      if (error.message.contains('user not found')) {
        throw Exception('User not found');
      } else if (error.message.contains('password is incorrect')) {
        throw Exception('Password is incorrect');
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container();
  }
}
