import 'package:sqflite/sqflite.dart';

void edgeCaseTests(Database db, String input) {
  // Scenario 1: Safe - Vulnerability in comments (Expected: Ignore)
  // db.rawQuery("SELECT * FROM users WHERE id = $input");

  // Scenario 2: Blindspot - Multi-line strings with odd whitespace (Expected: Catch if regex is good)
  db.rawQuery("SELECT * "
              "FROM users "
              "WHERE id = $input");

  // Scenario 3: Blindspot - Bizarre method formatting (Expected: Miss if regex expects tight spacing)
  db.
  rawQuery
  (
    "SELECT * FROM users WHERE id = " + input
  );
}
