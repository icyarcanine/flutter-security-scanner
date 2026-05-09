import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'package:supabase_flutter/supabase_flutter.dart';
import 'package:path/path.dart' as p;
import 'package:uuid/uuid.dart';

Future<void> main() async {
  await Supabase.initialize(
    url: const String.fromEnvironment('SUPABASE_URL'),
    anonKey: const String.fromEnvironment('SUPABASE_ANON_KEY'),
  );
  runApp(MaterialApp(home: UploadScreen()));
}

class UploadScreen extends StatelessWidget {
  Future<void> pickAndUpload() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['pdf', 'doc', 'docx'],
      allowMultiple: false,
    );

    if (result != null && result.files.single.path != null) {
      final file = result.files.single;
      final bytes = file.bytes;

      if (bytes == null || bytes.isEmpty) return;
      if (bytes.length > 5 * 1024 * 1024) {
        throw Exception('File too large');
      }

      // Sanitize file name using UUID
      final ext = p.extension(file.name).toLowerCase();
      final safeName = '${const Uuid().v4()}$ext';

      try {
        await Supabase.instance.client.storage
            .from('documents')
            .uploadBinary(safeName, bytes);
      } catch (e) {
        throw Exception('Upload failed');
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return ElevatedButton(
      onPressed: pickAndUpload,
      child: Text('Upload File'),
    );
  }
}
