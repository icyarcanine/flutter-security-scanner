import 'package:flutter/material.dart';
import 'package:supabase_flutter/supabase_flutter.dart';
import 'package:shared_preferences/shared_preferences.dart';

class AuthTestScreen extends StatefulWidget {
  const AuthTestScreen({super.key});

  @override
  State<AuthTestScreen> createState() => _AuthTestScreenState();
}

class _AuthTestScreenState extends State<AuthTestScreen> {
  String? _token;

  // BAD: OAuth without redirectTo - missing redirect URL validation
  Future<void> badOAuthSignIn() async {
    await Supabase.instance.client.auth.signInWithOAuth(
      OAuthProvider.google,
    );
  }

  // BAD: OAuth without PKCE explicit config on older client
  Future<void> badOAuthNoPKCE() async {
    await Supabase.instance.client.auth.signInWithOAuth(
      OAuthProvider.github,
    );
  }

  // GOOD: Proper OAuth with redirectTo
  Future<void> goodOAuthSignIn() async {
    await Supabase.instance.client.auth.signInWithOAuth(
      OAuthProvider.google,
      redirectTo: 'myapp://callback',
    );
  }

  // BAD: ID token without nonce
  Future<void> badAppleSignIn() async {
    await Supabase.instance.client.auth.signInWithIdToken(
      provider: OAuthProvider.apple,
      idToken: 'token_here',
    );
  }

  // GOOD: ID token with nonce
  Future<void> goodAppleSignIn() async {
    await Supabase.instance.client.auth.signInWithIdToken(
      provider: OAuthProvider.apple,
      idToken: 'token_here',
      nonce: 'random_nonce_123',
    );
  }

  // BAD: No brute-force protection
  Future<void> badPasswordSignIn(String email, String password) async {
    await Supabase.instance.client.auth.signInWithPassword(
      email: email,
      password: password,
    );
  }

  // GOOD: With rate limiting
  Future<void> goodPasswordSignIn(String email, String password) async {
    await Future.delayed(const Duration(seconds: 1)); // Rate limit
    await Supabase.instance.client.auth.signInWithPassword(
      email: email,
      password: password,
    );
  }

  // BAD: Storing token in plain variable
  Future<void> badTokenStorage() async {
    final session = await Supabase.instance.client.auth.getSession();
    _token = session?.accessToken; // Storing in plain variable
  }

  // BAD: Storing token in SharedPreferences
  Future<void> badPrefsStorage() async {
    final prefs = await SharedPreferences.getInstance();
    final session = await Supabase.instance.client.auth.getSession();
    await prefs.setString('auth_token', session?.accessToken ?? '');
  }

  // GOOD: Using secure storage
  Future<void> goodSecureStorage() async {
    // import 'package:flutter_secure_storage/flutter_secure_storage.dart';
    // const storage = FlutterSecureStorage();
    // final session = await Supabase.instance.client.auth.getSession();
    // await storage.write(key: 'auth_token', value: session?.accessToken);
  }

  // BAD: signOut without clearing local state
  Future<void> badSignOut() async {
    await Supabase.instance.client.auth.signOut();
    // Missing: clear local state, secure storage, memory
  }

  // GOOD: Complete signOut
  Future<void> goodSignOut() async {
    await Supabase.instance.client.auth.signOut();
    // await storage.deleteAll();
    // setState(() => _user = null);
  }

  // BAD: Using session without checking expiration
  Future<void> badSessionUse() async {
    final session = await Supabase.instance.client.auth.getSession();
    if (session != null) {
      // Using token without checking if expired
      await _makeApiCall(session.accessToken);
    }
  }

  // GOOD: Checking session expiration
  Future<void> goodSessionUse() async {
    final session = await Supabase.instance.client.auth.getSession();
    if (session != null && !session.isExpired) {
      await _makeApiCall(session.accessToken);
    }
  }

  Future<void> _makeApiCall(String token) async {
    // API call implementation
  }

  @override
  Widget build(BuildContext context) {
    return Container();
  }
}
