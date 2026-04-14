import 'package:http/http.dart' as http;
import 'package:supabase_flutter/supabase_flutter.dart';

Future<void> fetchData() async {
  final response = await http.get(Uri.parse('http://api.example.com/data'));
}

Future<void> fetchLocal() async {
  // This should NOT be flagged (localhost is okay for dev).
  final response = await http.get(Uri.parse('http://localhost:8080/api'));
}
