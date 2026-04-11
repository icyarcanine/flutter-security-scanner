import 'package:flutter/material.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

Future<void> main() async {
  // Bad: Hardcoding the anon key allows unauthorized access
  const anonKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature';

  await Supabase.initialize(
    url: 'https://demo-project.supabase.co',
    anonKey: anonKey,
  );

  final session = Supabase.instance.client.auth.currentSession;

  // Bad: Printing sensitive details to the console leaks memory and security info automatically in production
  print('Current session token starts with: ${session?.accessToken.substring(0, 5)}');

  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      home: Scaffold(
        body: Center(
          child: Text('Example Security Setup Demo'),
        ),
      ),
    );
  }
}
