import 'package:sqflite/sqflite.dart';

Future<Database> openAppDatabase() async {
  return openDatabase(
    'app.db',
    version: 1,
    onCreate: (db, v) async {
      await db.execute('CREATE TABLE users (id INTEGER, token TEXT)');
    },
  );
}
