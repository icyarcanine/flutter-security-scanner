import 'package:sqflite/sqflite.dart';

void sqlInjectionTests(Database db, String userInput) {
  // Scenario 1: Vulnerable - String Interpolation (Expected: Catch)
  db.rawQuery("SELECT * FROM users WHERE id = $userInput");

  // Scenario 2: Vulnerable - String Concatenation (Expected: Catch)
  db.execute("UPDATE users SET name = '" + userInput + "' WHERE id = 1");

  // Scenario 3: Safe - Parameterized Query (Expected: Safe)
  db.rawQuery("SELECT * FROM users WHERE id = ?", [userInput]);

  // Scenario 4: Blindspot - Deep Alias (Expected: Miss, because regex only checks first arg)
  final String query = "SELECT * FROM users WHERE id = $userInput";
  db.rawQuery(query);

  // Scenario 5: Vulnerable - Multi-line string interpolation (Expected: Catch)
  db.rawQuery('''
    SELECT * 
    FROM users 
    WHERE username = $userInput
  ''');

  // Scenario 6: Safe - Safe String Interpolation (Expected: Safe, but might FP if regex is poor)
  final String tableName = "users";
  db.rawQuery("SELECT * FROM $tableName"); // Should technically catch if regex just looks for $, but rule says "with SQL keywords"
}
