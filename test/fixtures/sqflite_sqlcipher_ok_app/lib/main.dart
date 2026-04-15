import 'package:sqflite_sqlcipher/sqflite.dart';

Future<Database> openEncryptedDatabase(String key) async {
  return openDatabase(
    'app.db',
    version: 1,
    password: key,
    onCreate: (db, v) async {
      await db.execute('CREATE TABLE users (id INTEGER, token TEXT)');
    },
  );
}
