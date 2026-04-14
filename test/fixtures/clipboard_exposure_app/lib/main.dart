import 'package:flutter/services.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

void copyToken(String accessToken) {
  Clipboard.setData(ClipboardData(text: accessToken));
}
