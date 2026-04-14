import 'package:supabase_flutter/supabase_flutter.dart';

Future<void> handleLinks() async {
  // Using getInitialLink without validating the URI
  final link = await getInitialLink();
  if (link != null) {
    navigateTo(link);
  }
}

Future<String?> getInitialLink() async => 'myapp://callback?token=abc';
void navigateTo(String url) {}
