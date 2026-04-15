import 'package:hive/hive.dart';
import 'package:hive_flutter/hive_flutter.dart';

Future<void> bootstrap() async {
  await Hive.initFlutter();
  final box = await Hive.openBox('profile');
  box.put('token', 'eyJhbGciOi.very.private');
}
