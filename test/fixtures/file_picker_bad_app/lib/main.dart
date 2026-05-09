import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

class UploadScreen extends StatelessWidget {
  Future<void> pickAndUpload() async {
    // No type restriction, no validation
    final result = await FilePicker.platform.pickFiles();

    if (result != null && result.files.single.path != null) {
      final file = result.files.single;
      // Using original file name without sanitization
      // No size validation before upload
      await Supabase.instance.client.storage
          .from('documents')
          .upload(file.name, file as dynamic);
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
