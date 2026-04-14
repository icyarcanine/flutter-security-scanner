import 'dart:io';

void downloadFile(String userPath) {
  // BAD: User-controlled path without validation
  final file = File('$userPath');
  file.readAsStringSync();
}
