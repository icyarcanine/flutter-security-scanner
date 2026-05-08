/// Parses SQL DDL files to extract table metadata relevant to security analysis.
///
/// Two types of owner-column references are detected:
///
/// 1. **Explicit FK:**  `actor_id uuid references auth.users(id)`
///    or `REFERENCES users(id)`.  These are unambiguous (100 % confidence).
///
/// 2. **Implicit convention:** A column whose name appears in
///    [DdlMetadata.knownUserFkColumnNames] and whose type is `uuid`.  This
///    covers the common pattern where schema designers omit the FK constraint
///    but follow the naming convention (`actor_id`, `performed_by`, etc.).
///
/// Only columns pointing to `auth.users` / `users` are registered — the
/// scanner does NOT claim ownership semantics for arbitrary FK columns
/// (e.g. `post_id references posts(id)`).
library;

import '../models/scanned_file.dart';

/// Table-level metadata extracted from SQL DDL.
class DdlMetadata {
  /// Maps lowercased table name → set of column names that reference users.
  ///
  /// Example: `{'audit_log': {'actor_id'}, 'posts': {'user_id'}}`
  final Map<String, Set<String>> userFkColumns;

  /// Tables with committed DDL that enables RLS.
  final Set<String> rlsEnabledTables;

  /// Maps lowercased table name → policy operations declared in committed DDL.
  ///
  /// Operations are `select`, `insert`, `update`, `delete`, or `all`.
  final Map<String, Set<String>> rlsPolicyOperations;

  /// SQL functions declared with `SECURITY DEFINER`.
  final Set<String> securityDefinerFunctions;

  /// Security-definer SQL functions without a recognizable auth guard.
  final Set<String> unsafeSecurityDefinerFunctions;

  const DdlMetadata(
    this.userFkColumns, {
    this.rlsEnabledTables = const {},
    this.rlsPolicyOperations = const {},
    this.securityDefinerFunctions = const {},
    this.unsafeSecurityDefinerFunctions = const {},
  });

  /// Returns the discovered owner columns for [tableName], or null if the
  /// table is unknown to DDL.
  Set<String>? forTable(String tableName) =>
      userFkColumns[tableName.toLowerCase()];

  /// Returns a combined set of all known tables (lowercased).
  Set<String> get knownTables => userFkColumns.keys.toSet();

  /// Returns true when committed SQL enables RLS for [tableName].
  bool hasRlsEnabled(String tableName) =>
      rlsEnabledTables.contains(tableName.toLowerCase());

  /// Returns true when committed SQL defines at least one policy for [tableName].
  bool hasAnyPolicy(String tableName) =>
      rlsPolicyOperations.containsKey(tableName.toLowerCase());

  /// Returns true when the scan has table-specific RLS evidence.
  bool hasRlsEvidenceForTable(String tableName) {
    final normalized = tableName.toLowerCase();
    return rlsEnabledTables.contains(normalized) ||
        rlsPolicyOperations.containsKey(normalized);
  }

  /// Returns true when committed policies cover the Supabase client operation.
  bool hasPolicyForOperation(String tableName, String operation) {
    final operations = rlsPolicyOperations[tableName.toLowerCase()];
    if (operations == null || operations.isEmpty) {
      return false;
    }
    if (operations.contains('all')) {
      return true;
    }
    final normalizedOperation = operation.toLowerCase();
    if (normalizedOperation == 'upsert') {
      return operations.contains('insert') && operations.contains('update');
    }
    return operations.contains(normalizedOperation);
  }

  /// Returns true when [functionName] is a committed `SECURITY DEFINER`
  /// function with no local auth guard that this scanner can recognize.
  bool isUnsafeSecurityDefinerFunction(String functionName) =>
      unsafeSecurityDefinerFunctions.contains(functionName.toLowerCase());

  /// Parse [sqlFiles] and extract user-FK column metadata.
  static DdlMetadata fromSqlFiles(Iterable<ScannedFile> sqlFiles) {
    final columns = <String, Set<String>>{};
    final rlsEnabledTables = <String>{};
    final policyOperations = <String, Set<String>>{};
    final securityDefinerFunctions = <String>{};
    final unsafeSecurityDefinerFunctions = <String>{};

    for (final file in sqlFiles) {
      _parseFile(
        file.content,
        columns,
        rlsEnabledTables,
        policyOperations,
        securityDefinerFunctions,
        unsafeSecurityDefinerFunctions,
      );
    }

    return DdlMetadata(
      _freezeSetMap(columns),
      rlsEnabledTables: Set.unmodifiable(rlsEnabledTables),
      rlsPolicyOperations: _freezeSetMap(policyOperations),
      securityDefinerFunctions: Set.unmodifiable(securityDefinerFunctions),
      unsafeSecurityDefinerFunctions:
          Set.unmodifiable(unsafeSecurityDefinerFunctions),
    );
  }

  /// DDL parsing state machine.
  static void _parseFile(
    String sql,
    Map<String, Set<String>> out,
    Set<String> rlsEnabledTables,
    Map<String, Set<String>> policyOperations,
    Set<String> securityDefinerFunctions,
    Set<String> unsafeSecurityDefinerFunctions,
  ) {
    // We use a lightweight state machine rather than a full SQL parser.
    // The patterns we care about are simple enough for regex + positional
    // stripping of string literals and comments.

    final cleaned = _stripCommentsAndStrings(sql);
    _extractCreateTables(cleaned, out);
    _extractAlterTableUserFk(cleaned, out);
    _extractRlsEnabledTables(cleaned, rlsEnabledTables);
    _extractCreatePolicies(cleaned, policyOperations);
    _extractSecurityDefinerFunctions(
      cleaned,
      securityDefinerFunctions,
      unsafeSecurityDefinerFunctions,
    );
  }

  static Map<String, Set<String>> _freezeSetMap(
    Map<String, Set<String>> source,
  ) {
    return Map.unmodifiable({
      for (final entry in source.entries)
        entry.key: Set.unmodifiable(entry.value),
    });
  }

  /// Strips SQL comments (-- and /* */) and string literals ('...') so that
  /// our regex patterns don't match inside human text or SQL values.
  ///
  /// Two-pass strategy (DF-4): first try the aggressive scrub that consumes
  /// the entire string-literal content. If that detects an unterminated
  /// quote (common while migrations are mid-edit), fall back to a
  /// conservative scrub that only masks the `'` character itself — this
  /// preserves any `CREATE TABLE` that appears after the broken literal so
  /// we don't silently drop later DDL.
  static String _stripCommentsAndStrings(String sql) {
    final aggressive = _scrub(sql, conservativeStrings: false);
    if (aggressive.unterminatedString) {
      return _scrub(sql, conservativeStrings: true).text;
    }
    return aggressive.text;
  }

  static _ScrubResult _scrub(String sql, {required bool conservativeStrings}) {
    final buf = StringBuffer();
    var i = 0;
    final len = sql.length;
    var unterminated = false;

    while (i < len) {
      final ch = sql[i];

      // Single-line comment: --
      if (ch == '-' && i + 1 < len && sql[i + 1] == '-') {
        i += 2;
        while (i < len && sql[i] != '\n') {
          i++;
        }
        continue;
      }

      // Block comment: /* ... */
      if (ch == '/' && i + 1 < len && sql[i + 1] == '*') {
        i += 2;
        var depth = 1;
        while (i + 1 < len && depth > 0) {
          if (sql[i] == '*' && sql[i + 1] == '/') {
            depth--;
            i += 2;
          } else {
            i++;
          }
        }
        continue;
      }

      // String literal: '...'  (escape '' for embedded quote)
      if (ch == '\'') {
        if (conservativeStrings) {
          // Conservative: mask the quote itself, leave subsequent chars
          // alone. Used as the fallback when the aggressive pass detected
          // an unterminated literal.
          buf.write(' ');
          i++;
          continue;
        }
        buf.write(' '); // replace with space (preserves token boundaries)
        i++;
        var closed = false;
        while (i < len) {
          if (sql[i] == '\'') {
            i++;
            if (i < len && sql[i] == '\'') {
              // escaped quote ''
              i++;
              continue;
            }
            closed = true;
            break;
          }
          i++;
        }
        buf.write(' ');
        if (!closed) {
          unterminated = true;
        }
        continue;
      }

      buf.write(ch);
      i++;
    }

    return _ScrubResult(buf.toString(), unterminated);
  }

  /// Finds `ALTER TABLE <name> ADD [CONSTRAINT <c>] FOREIGN KEY (<cols>)
  /// REFERENCES (auth.)?users(...)` and registers each captured column as
  /// an owner candidate for the altered table. Composite-column FKs are
  /// supported via comma-separated capture; both schemas (`auth.users` and
  /// bare `users`) are accepted.
  static void _extractAlterTableUserFk(
    String cleaned,
    Map<String, Set<String>> out,
  ) {
    final statementPattern = RegExp(
      r'''ALTER\s+TABLE\b[\s\S]*?(?:;|$)''',
      caseSensitive: false,
    );
    final tablePattern = RegExp(
      r'''ALTER\s+TABLE\s+(?:ONLY\s+)?'''
      r'''(?:public\.|auth\.|storage\.|real-time\.)?'''
      r'''([a-zA-Z_]\w*)\b''',
      caseSensitive: false,
    );
    final fkPattern = RegExp(
      r'''ADD\s+(?:CONSTRAINT\s+\w+\s+)?'''
      r'''FOREIGN\s+KEY\s*\(\s*([a-zA-Z_]\w*(?:\s*,\s*[a-zA-Z_]\w*)*)\s*\)\s*'''
      r'''REFERENCES\s+(?:auth\.)?users\b''',
      caseSensitive: false,
    );

    for (final statementMatch in statementPattern.allMatches(cleaned)) {
      final statement = statementMatch.group(0)!;
      final tableMatch = tablePattern.firstMatch(statement);
      final fkMatch = fkPattern.firstMatch(statement);
      if (tableMatch == null || fkMatch == null) {
        continue;
      }

      final tableName = tableMatch.group(1)!.toLowerCase();
      final columnList = fkMatch.group(1)!;
      final entry = out.putIfAbsent(tableName, () => <String>{});
      for (final col in columnList.split(',')) {
        entry.add(col.trim().toLowerCase());
      }
    }
  }

  /// Finds `ALTER TABLE <name> ENABLE ROW LEVEL SECURITY` and
  /// `ALTER TABLE <name> FORCE ROW LEVEL SECURITY` statements.
  static void _extractRlsEnabledTables(String cleaned, Set<String> out) {
    final statementPattern = RegExp(
      r'''ALTER\s+TABLE\b[\s\S]*?(?:;|$)''',
      caseSensitive: false,
    );
    final tablePattern = RegExp(
      r'''ALTER\s+TABLE\s+(?:ONLY\s+)?'''
      r'''(?:public\.|auth\.|storage\.|real-time\.)?'''
      r'''([a-zA-Z_]\w*)\b''',
      caseSensitive: false,
    );
    final rlsPattern = RegExp(
      r'''\b(?:ENABLE|FORCE)\s+ROW\s+LEVEL\s+SECURITY\b''',
      caseSensitive: false,
    );

    for (final statementMatch in statementPattern.allMatches(cleaned)) {
      final statement = statementMatch.group(0)!;
      if (!rlsPattern.hasMatch(statement)) {
        continue;
      }
      final tableMatch = tablePattern.firstMatch(statement);
      if (tableMatch == null) {
        continue;
      }
      out.add(tableMatch.group(1)!.toLowerCase());
    }
  }

  /// Finds `CREATE POLICY ... ON <table> [FOR <operation>]` statements.
  ///
  /// PostgreSQL defaults omitted `FOR` clauses to `ALL`, so those are stored
  /// as `all`. The policy expression is deliberately not interpreted here;
  /// this pass only proves that committed DDL contains a table/operation
  /// policy to review.
  static void _extractCreatePolicies(
    String cleaned,
    Map<String, Set<String>> out,
  ) {
    final statementPattern = RegExp(
      r'''CREATE\s+POLICY\b[\s\S]*?(?:;|$)''',
      caseSensitive: false,
    );
    final tablePattern = RegExp(
      r'''\bON\s+(?:TABLE\s+)?(?:public\.|auth\.|storage\.|real-time\.)?([a-zA-Z_]\w*)\b''',
      caseSensitive: false,
    );
    final operationPattern = RegExp(
      r'''\bFOR\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\b''',
      caseSensitive: false,
    );

    for (final statementMatch in statementPattern.allMatches(cleaned)) {
      final statement = statementMatch.group(0)!;
      final tableMatch = tablePattern.firstMatch(statement);
      if (tableMatch == null) {
        continue;
      }

      final table = tableMatch.group(1)!.toLowerCase();
      final operation =
          operationPattern.firstMatch(statement)?.group(1)?.toLowerCase() ??
              'all';
      out.putIfAbsent(table, () => <String>{}).add(operation);
    }
  }

  /// Finds SQL functions that run as `SECURITY DEFINER`.
  ///
  /// Supabase exposes public SQL functions through PostgREST RPC. A
  /// security-definer function runs with the function owner's privileges, so
  /// a client-side `supabase.rpc('fn')` call into one of these functions is
  /// dangerous unless the function body performs its own auth check.
  static void _extractSecurityDefinerFunctions(
    String cleaned,
    Set<String> allSecurityDefiners,
    Set<String> unsafeSecurityDefiners,
  ) {
    final functionPattern = RegExp(
      r'''CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+'''
      r'''(?:(public|auth|storage|real-time)\.)?([a-zA-Z_]\w*)\s*'''
      r'''\([\s\S]*?'''
      r'''(?=\n\s*(?:CREATE|ALTER|DROP|GRANT|REVOKE)\b|$)''',
      caseSensitive: false,
    );
    final securityDefinerPattern = RegExp(
      r'''\bSECURITY\s+DEFINER\b''',
      caseSensitive: false,
    );
    final authGuardPattern = RegExp(
      r'''\bauth\.uid\s*\(|\bauth\.role\s*\(|\bcurrent_setting\s*\(|\brequest\.jwt\b|\bjwt\b''',
      caseSensitive: false,
    );

    for (final match in functionPattern.allMatches(cleaned)) {
      final schema = match.group(1)?.toLowerCase();
      // PostgREST exposes public functions. Schema-less declarations normally
      // land in the current search_path, which Supabase migrations commonly
      // use for `public`, so include schema-less and explicit public only.
      if (schema != null && schema != 'public') {
        continue;
      }

      final functionName = match.group(2)!.toLowerCase();
      final statement = match.group(0)!;
      if (!securityDefinerPattern.hasMatch(statement)) {
        continue;
      }

      allSecurityDefiners.add(functionName);
      if (!authGuardPattern.hasMatch(statement)) {
        unsafeSecurityDefiners.add(functionName);
      }
    }
  }

  /// Finds all `CREATE TABLE ... ( ... )` statements and extracts
  /// user-FK column references.
  static void _extractCreateTables(
    String cleaned,
    Map<String, Set<String>> out,
  ) {
    final createTablePattern = RegExp(
      r'''CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?'''
      r'''(?:public\.|auth\.|storage\.|real-time\.)?'''
      r'''([a-zA-Z_]\w*)\s*\('''
      r'''((?:[^()]+|\([^()]*\))*)\s*\)''',
      caseSensitive: false,
    );

    for (final match in createTablePattern.allMatches(cleaned)) {
      final tableName = match.group(1)!.toLowerCase();
      final columnsBlock = match.group(2)!;

      final fkColumns = _extractUserFkColumns(columnsBlock);
      if (fkColumns.isNotEmpty) {
        out.putIfAbsent(tableName, () => <String>{});
        out[tableName]!.addAll(fkColumns);
      }
    }
  }

  /// Canonical column names that strongly indicate a FK to `auth.users.id`.
  ///
  /// Single source of truth for both the DDL parser's Pass-2 naming-convention
  /// heuristic and the Tier-3 fallback in
  /// [`ownerColumnsForTable`](../models/project_context.dart). The two
  /// registries previously diverged (4 entries vs 13); both now point here.
  static const knownUserFkColumnNames = <String>{
    'actor_id',
    'user_id',
    'owner_id',
    'author_id',
    'created_by',
    'performed_by',
    'assigned_to',
    'updated_by',
    'deleted_by',
    'modified_by',
    'reviewed_by',
    'approved_by',
    'requested_by',
  };

  /// Extracts user-FK column names from the column-definitions block of a
  /// CREATE TABLE statement.
  ///
  /// Two passes:
  /// 1. Inline `REFERENCES (auth.)?users(\(id\))?` → unambiguous match.
  /// 2. Naming convention: column named in [knownUserFkColumnNames] with
  ///    type `uuid`.
  static Set<String> _extractUserFkColumns(String columnsBlock) {
    final result = <String>{};

    // Pass 1: Explicit FK constraint (single-column AND composite).
    //
    // Matches patterns like:
    //   actor_id uuid references auth.users(id)
    //   user_id uuid references users
    //   CONSTRAINT fk FOREIGN KEY (actor_id) REFERENCES auth.users(id)
    //   CONSTRAINT fk FOREIGN KEY (actor_id, tenant_id) REFERENCES auth.users(id, tenant_id)
    //
    // The capture group accepts a comma-separated identifier list so the
    // composite-FK case is recognised; previously the pattern hard-required
    // a single identifier and produced NO MATCH (silent FN) on multi-column
    // refs (DF-5). Each captured column is registered as an owner candidate.
    final explicitFkPattern = RegExp(
      r'''FOREIGN\s+KEY\s*\(\s*([a-zA-Z_]\w*(?:\s*,\s*[a-zA-Z_]\w*)*)\s*\)\s*'''
      r'''REFERENCES\s+(?:auth\.)?users\b''',
      caseSensitive: false,
    );
    for (final m in explicitFkPattern.allMatches(columnsBlock)) {
      for (final col in m.group(1)!.split(',')) {
        result.add(col.trim().toLowerCase());
      }
    }

    // Inline column-level references:
    //   column_name uuid references (auth.)?users(\(id\))?
    final inlineFkPattern = RegExp(
      r'''([a-zA-Z_]\w*)\s+uuid\b[^,;]*?'''
      r'''REFERENCES\s+(?:auth\.)?users\b''',
      caseSensitive: false,
    );
    for (final m in inlineFkPattern.allMatches(columnsBlock)) {
      result.add(m.group(1)!.toLowerCase());
    }

    // Pass 2: Naming convention heuristic.
    //
    // Match columns matching knownUserFkColumnNames with uuid type.
    // This catches the fixture pattern:
    //   actor_id uuid not null
    final conventionPattern = RegExp(
      r'''([a-zA-Z_]\w*)\s+uuid\b''',
      caseSensitive: false,
    );
    for (final m in conventionPattern.allMatches(columnsBlock)) {
      final col = m.group(1)!.toLowerCase();
      if (knownUserFkColumnNames.contains(col)) {
        result.add(col);
      }
    }

    return result;
  }
}

/// Internal result of `DdlMetadata._scrub`: scrubbed text plus a flag set
/// when an unterminated string literal was detected during the aggressive
/// pass. Drives the DF-4 conservative-fallback path.
class _ScrubResult {
  final String text;
  final bool unterminatedString;
  const _ScrubResult(this.text, this.unterminatedString);
}
