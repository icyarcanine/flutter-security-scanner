import 'package:flutter/material.dart';

class IntentTestWidget extends StatelessWidget {
  const IntentTestWidget({super.key});

  // BAD: Using intent data without validation
  void handleIntentData(BuildContext context, dynamic intentData) {
    final filePath = intentData['file_path'];
    // No validation before using the path
    _processFile(filePath);
  }

  // GOOD: Validating intent data
  void handleIntentDataSecure(BuildContext context, dynamic intentData) {
    final filePath = intentData['file_path'];
    if (_isValidFilePath(filePath)) {
      _processFile(filePath);
    }
  }

  bool _isValidFilePath(String? path) {
    if (path == null) return false;
    // Validate path doesn't contain traversal sequences
    if (path.contains('..')) return false;
    // Validate expected extension
    return path.endsWith('.pdf') || path.endsWith('.jpg');
  }

  void _processFile(String? filePath) {
    // Process file
  }

  @override
  Widget build(BuildContext context) {
    return Container();
  }
}
