import 'dart:convert';
import 'dart:io';

import '../utils/path_utils.dart';
import 'scanned_file.dart';

/// Describes how strongly a project signals that Row-Level Security is set up.
enum RlsEvidenceLevel {
  /// DDL found: `CREATE POLICY` or `ENABLE ROW LEVEL SECURITY` in SQL files.
  strong,

  /// Soft signals only: `auth.uid()` in Dart/Markdown, or a generic textual
  /// mention of "row level security" without concrete DDL.
  weak,

  /// No RLS-related evidence found anywhere in the scanned files.
  none,
}

class ProjectContext {
  ProjectContext._({required this.rootPath, required this.files});

  final String rootPath;
  final List<ScannedFile> files;

  static const _ignoredDirectories = {
    '.dart_tool',
    '.git',
    '.idea',
    '.vscode',
    'build',
    'coverage',
    'dist',
    'node_modules',
    'Pods',
  };

  static const _supportedExtensions = {
    '.dart',
    '.yaml',
    '.yml',
    '.sql',
    '.md',
    '.txt',
    '.json',
    '.plist',
    '.xml',
    '.properties',
    '.gradle',
    '.kts', // Kotlin-DSL Gradle files (build.gradle.kts, settings.gradle.kts)
    '.kt',
    '.swift',
    '.java',
    '.env',
    '.toml', // supabase/config.toml, Cargo.toml, pyproject.toml, …
    // Web surfaces: Supabase Edge Functions (Deno/TS), and web clients
    // that share the same Supabase project key material.
    '.ts',
    '.tsx',
    '.js',
    '.jsx',
    '.mjs',
    '.cjs',
  };

  static ProjectContext load(
    String rootPath, {
    bool Function(String relativePath)? excludePath,
  }) {
    final rootDirectory = Directory(rootPath).absolute;
    final files = <ScannedFile>[];

    void walk(Directory directory) {
      List<FileSystemEntity> entities;
      try {
        entities = directory.listSync(followLinks: false);
      } on FileSystemException {
        return;
      }

      for (final entity in entities) {
        final entityName = basename(entity.path);
        if (entity is Directory) {
          if (_ignoredDirectories.contains(entityName)) {
            continue;
          }
          // Also honour user-configured directory excludes so the walker
          // does not recurse into huge trees we're going to drop anyway.
          final dirRelative = relativePath(rootDirectory.path, entity.path);
          if (excludePath != null && excludePath(dirRelative)) {
            continue;
          }
          walk(entity);
          continue;
        }

        if (entity is! File) {
          continue;
        }

        final relative = relativePath(rootDirectory.path, entity.path);
        if (!_shouldScan(relative)) {
          continue;
        }
        if (excludePath != null && excludePath(relative)) {
          continue;
        }

        files.add(
          ScannedFile(
            absolutePath: normalizePath(entity.absolute.path),
            relativePath: relative,
            content: _readTextFile(entity),
          ),
        );
      }
    }

    walk(rootDirectory);

    files.sort(
      (left, right) => left.relativePath.compareTo(right.relativePath),
    );

    return ProjectContext._(
      rootPath: normalizePath(rootDirectory.path),
      files: files,
    );
  }

  Iterable<ScannedFile> get dartFiles => files.where((file) => file.isDart);
  Iterable<ScannedFile> get appDartFiles => dartFiles.where(
    (file) => !_isTestLikePath(file.relativePath) && !_isGeneratedCode(file),
  );
  Iterable<ScannedFile> get supabaseCandidateDartFiles =>
      appDartFiles.where(_looksLikeSupabaseFile);
  Iterable<ScannedFile> get envFiles => files.where((file) => file.isEnvFile);
  Iterable<ScannedFile> get sqlFiles => files.where((file) => file.isSql);
  Iterable<ScannedFile> get markdownFiles =>
      files.where((file) => file.isMarkdown);
  Iterable<ScannedFile> get yamlFiles => files.where((file) => file.isYaml);

  ScannedFile? get pubspecFile {
    for (final file in files) {
      if (file.relativePath == 'pubspec.yaml') {
        return file;
      }
    }
    return null;
  }

  bool get usesSupabaseFlutter =>
      _fileContains(
        pubspecFile,
        RegExp(r'(^|\s)supabase_flutter\s*:', multiLine: true),
      ) ||
      _filesContain(
        appDartFiles,
        RegExp(r'''package:supabase_flutter/supabase_flutter\.dart'''),
      );

  bool get usesSupabaseDart =>
      _fileContains(
        pubspecFile,
        RegExp(r'(^|\s)supabase\s*:', multiLine: true),
      ) ||
      _filesContain(
        appDartFiles,
        RegExp(r'''package:supabase/supabase\.dart'''),
      );

  bool get usesSupabase =>
      usesSupabaseFlutter ||
      usesSupabaseDart ||
      _filesContain(appDartFiles, _supabaseUsagePattern);

  bool get usesDotenv =>
      _fileContains(
        pubspecFile,
        RegExp(r'(^|\s)flutter_dotenv\s*:', multiLine: true),
      ) ||
      _filesContain(appDartFiles, RegExp(r'''dotenv\.env'''));

  bool get usesDartDefine =>
      _filesContain(appDartFiles, RegExp(r'''String\.fromEnvironment\s*\('''));

  bool get hasSupabaseInitialize =>
      _filesContain(appDartFiles, RegExp(r'''Supabase\.initialize\s*\('''));

  bool get hasEnvFile => envFiles.any((file) => !file.isEnvTemplateFile);

  bool get hasExampleEnvFile => envFiles.any((file) => file.isEnvTemplateFile);

  List<EnvEntry> get envEntries => _envEntries ??= _computeEnvEntries();
  List<EnvEntry>? _envEntries;

  List<EnvEntry> _computeEnvEntries() {
    final entries = <EnvEntry>[];
    final pattern = RegExp(
      r'^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$',
      multiLine: true,
    );
    for (final file in envFiles) {
      for (final match in pattern.allMatches(file.content)) {
        final value = match.group(2)!;
        if (value.startsWith('#')) {
          continue;
        }
        entries.add(
          EnvEntry(
            key: match.group(1)!,
            value: _stripQuotes(value),
            file: file,
            line: file.lineForOffset(match.start),
          ),
        );
      }
    }
    return entries;
  }

  List<TableAccess> get tableAccesses =>
      _tableAccesses ??= _computeTableAccesses();
  List<TableAccess>? _tableAccesses;

  List<TableAccess> _computeTableAccesses() {
    final accesses = <TableAccess>[];
    final pattern = RegExp(r'''\.from\(\s*['"]([a-zA-Z0-9_:-]+)['"]\s*\)''');

    for (final file in supabaseCandidateDartFiles) {
      for (final match in pattern.allMatches(file.content)) {
        final prefixStart = match.start - 30 < 0 ? 0 : match.start - 30;
        final prefix = file.content.substring(prefixStart, match.start);
        if (prefix.contains('.storage')) {
          continue;
        }

        final snippet = _statementSnippet(file.content, match.start, 360);
        // Use a capturing group so we can extract just the operation name.
        final operationMatch = RegExp(
          r'''\.(select|insert|update|delete|upsert)\s*\(''',
          caseSensitive: false,
        ).firstMatch(snippet);
        if (operationMatch == null) {
          continue;
        }

        final table = match.group(1)!;
        final line = file.lineForOffset(match.start);
        final expectedColumns = ownerColumnsForTable(table);
        final localContext = file.contextAroundLine(line, before: 40, after: 2);
        accesses.add(
          TableAccess(
            table: table,
            operation: operationMatch.group(1)!.toLowerCase(),
            file: file,
            line: line,
            snippet: snippet,
            localContext: localContext,
            hasOwnershipFilter:
                expectedColumns.isNotEmpty &&
                _hasOwnershipFilter(snippet, expectedColumns),
            usesClientProvidedUserId:
                expectedColumns.isNotEmpty &&
                _usesClientProvidedUserId(
                  snippet,
                  localContext,
                  expectedColumns,
                ),
            referencesCurrentUser: RegExp(
              r'''currentUser|auth\.user|auth\.currentUser''',
            ).hasMatch(snippet),
          ),
        );
      }
    }

    return accesses;
  }

  List<StorageBucketUse> get storageBucketUses =>
      _storageBucketUses ??= _computeStorageBucketUses();
  List<StorageBucketUse>? _storageBucketUses;

  List<StorageBucketUse> _computeStorageBucketUses() {
    final buckets = <StorageBucketUse>[];
    final pattern = RegExp(
      r'''\.storage\s*\.from\(\s*['"]([a-zA-Z0-9_.-]+)['"]\s*\)''',
    );
    // Regex to detect user-identity strings in upload path arguments.
    // Matches: $userId, ${user.id}, $uid, currentUser.id, auth.uid(), user.id
    final userPathPattern = RegExp(
      r'''\$(userId|uid)\b|\$\{[^}]*(\.id|uid)[^}]*\}|currentUser\.id|auth\.uid\(\)|user\.id\b|\buid\b''',
      caseSensitive: false,
    );

    // Regex to detect sensitive file contexts in upload strings.
    final sensitiveContextPattern = RegExp(
      r'''avatar|profile|user|private''',
      caseSensitive: false,
    );

    for (final file in appDartFiles) {
      for (final match in pattern.allMatches(file.content)) {
        // Grab extra context after the .from(...) call to capture .upload(path, ...).
        final snippet = _statementSnippet(file.content, match.start, 320);
        final opMatch = RegExp(
          r'''\.(upload|uploadBinary|download|list|remove|getPublicUrl)\s*\(''',
          caseSensitive: false,
        ).firstMatch(snippet);

        // Extract just the first argument to the upload call (the path string).
        String? uploadPath;
        if (opMatch != null) {
          final afterOp = snippet.substring(opMatch.end);
          // Grab up to 200 chars or the first unbalanced comma/paren.
          uploadPath = afterOp.length > 200
              ? afterOp.substring(0, 200)
              : afterOp;
        }

        buckets.add(
          StorageBucketUse(
            bucketName: match.group(1)!,
            operation: opMatch?.group(1)?.toLowerCase() ?? 'access',
            file: file,
            line: file.lineForOffset(match.start),
            pathHasUserIdPattern:
                uploadPath != null && userPathPattern.hasMatch(uploadPath),
            pathHasSensitiveContext:
                uploadPath != null &&
                sensitiveContextPattern.hasMatch(uploadPath),
          ),
        );
      }
    }

    return buckets;
  }

  List<UploadCall> get uploadCalls => _uploadCalls ??= _computeUploadCalls();
  List<UploadCall>? _uploadCalls;

  List<UploadCall> _computeUploadCalls() {
    final uploads = <UploadCall>[];
    final pattern = RegExp(r'''\.upload(?:Binary)?\s*\(''');

    for (final file in appDartFiles) {
      for (final match in pattern.allMatches(file.content)) {
        final line = file.lineForOffset(match.start);
        final context = file.contextAroundLine(line, before: 12, after: 6);
        uploads.add(
          UploadCall(
            file: file,
            line: line,
            hasTypeValidation: RegExp(
              r'''mime|contentType|lookupMimeType|allowedTypes|allowedExtensions|endsWith\(['"].+\.[a-z0-9]+['"]\)|fileType''',
              caseSensitive: false,
            ).hasMatch(context),
            hasSizeValidation:
                RegExp(
                  r'''(if|assert)\s*\([^)]*\b(fileSize|sizeInBytes|contentLength|bytes\.length|lengthSync\(\)|pickedFile\.size|maxSize|maxFileSize|maxUploadSize)\b[^)]*\)|\b(fileSize|sizeInBytes|contentLength|bytes\.length|lengthSync\(\)|pickedFile\.size)\b[^;\n]{0,40}(<=|<|>=|>)|(?:<=|<|>=|>)[^;\n]{0,40}\b(fileSize|sizeInBytes|contentLength|bytes\.length|lengthSync\(\)|pickedFile\.size|maxSize|maxFileSize|maxUploadSize)\b''',
                  caseSensitive: false,
                ).hasMatch(context) ||
                (RegExp(
                      r'''\b(?:file|image|video|media|byte|picked|asset|upload)[a-zA-Z0-9_]*\.(length\(\)|size\b)''',
                      caseSensitive: false,
                    ).hasMatch(context) &&
                    RegExp(
                      r'''\b(?:size|length)\b\s*(?:<=|<|>=|>)\s*\d+''',
                      caseSensitive: false,
                    ).hasMatch(context)),
            hasValidationHelper: _hasNearbyValidationHelperCall(file, line),
          ),
        );
      }
    }

    return uploads;
  }

  int get directSupabaseClientCount => supabaseClientLocations.length;

  List<Location> get supabaseClientLocations =>
      _supabaseClientLocations ??= _computeSupabaseClientLocations();
  List<Location>? _supabaseClientLocations;

  List<Location> _computeSupabaseClientLocations() {
    final locations = <Location>[];
    final pattern = RegExp(r'''\bSupabaseClient\s*\(''');
    for (final file in appDartFiles) {
      for (final match in pattern.allMatches(file.content)) {
        locations.add(
          Location(file: file, line: file.lineForOffset(match.start)),
        );
      }
    }
    return locations;
  }

  /// Backward-compat shim: true when evidence level is not [RlsEvidenceLevel.none].
  bool get hasRlsEvidence => rlsEvidenceLevel != RlsEvidenceLevel.none;

  RlsEvidenceLevel get rlsEvidenceLevel =>
      _rlsEvidenceLevel ??= _computeRlsEvidenceLevel();
  RlsEvidenceLevel? _rlsEvidenceLevel;

  RlsEvidenceLevel _computeRlsEvidenceLevel() {
    // Strong: actual DDL in SQL files.
    for (final file in sqlFiles) {
      final codeOnly = _stripSqlComments(file.content);
      if (_strongRlsPattern.hasMatch(codeOnly)) {
        return RlsEvidenceLevel.strong;
      }
    }

    // Weak in SQL (generic textual mention, no DDL).
    for (final file in sqlFiles) {
      final codeOnly = _stripSqlComments(file.content);
      if (_weakRlsPattern.hasMatch(codeOnly)) {
        return RlsEvidenceLevel.weak;
      }
    }

    // auth.uid() in Dart source → developer is writing policies, strong-ish.
    if (_filesContain(appDartFiles, _authUidPattern, stripDartComments: true)) {
      return RlsEvidenceLevel.strong;
    }

    // Generic textual mention in Dart or Markdown.
    // We do NOT strip comments from Dart/Markdown for "weak" pattern since comments
    // ("// TODO: add RLS") are exactly what constitutes weak evidence there.
    if (_filesContain(appDartFiles, _weakRlsPattern) ||
        _filesContain(markdownFiles, _weakRlsPattern)) {
      return RlsEvidenceLevel.weak;
    }

    return RlsEvidenceLevel.none;
  }

  static String _stripSqlComments(String content) {
    return content
        .replaceAll(RegExp(r'''/\*[\s\S]*?\*/'''), '')
        .replaceAll(RegExp(r'''--.*'''), '');
  }

  static String _stripDartComments(String content) {
    return content
        .replaceAll(RegExp(r'''/\*[\s\S]*?\*/'''), '')
        .replaceAll(RegExp(r'''//.*'''), '');
  }

  bool gitignoreCoversEnvFile(String envFilePath) {
    final gitignore = files.where((file) => file.isGitIgnore).toList()
      ..sort((left, right) {
        final leftDepth = _pathDepth(left.relativePath);
        final rightDepth = _pathDepth(right.relativePath);
        if (leftDepth != rightDepth) {
          return leftDepth.compareTo(rightDepth);
        }
        return left.relativePath.compareTo(right.relativePath);
      });
    if (gitignore.isEmpty) {
      return false;
    }

    var isIgnored = false;
    for (final file in gitignore) {
      final gitignoreDirectory = dirname(file.relativePath);
      for (final rawLine in file.lines) {
        final line = rawLine.trim();
        if (line.isEmpty || line.startsWith('#')) {
          continue;
        }
        final isNegated = line.startsWith('!');
        final pattern = isNegated ? line.substring(1) : line;
        if (_gitignorePatternMatches(
          pattern: pattern,
          targetPath: envFilePath,
          gitignoreDirectory: gitignoreDirectory,
        )) {
          isIgnored = !isNegated;
        }
      }
    }

    return isIgnored;
  }

  static bool _shouldScan(String relativePathValue) {
    final name = basename(relativePathValue);
    if (name == '.gitignore' || name == '.env' || name.startsWith('.env.')) {
      return true;
    }

    final dotIndex = name.lastIndexOf('.');
    if (dotIndex == -1) {
      return false;
    }

    return _supportedExtensions.contains(name.substring(dotIndex));
  }

  static String _snippetFrom(String content, int start, int maxLength) {
    final end = (start + maxLength).clamp(0, content.length);
    return content.substring(start, end);
  }

  static String _statementSnippet(String content, int start, int maxLength) {
    final rawSnippet = _snippetFrom(content, start, maxLength);
    final semicolonIndex = rawSnippet.indexOf(';');
    if (semicolonIndex == -1) {
      return rawSnippet;
    }

    return rawSnippet.substring(0, semicolonIndex + 1);
  }

  static bool _hasOwnershipFilter(String snippet, Set<String> expectedColumns) {
    for (final column in expectedColumns) {
      final pattern = RegExp(
        "\\.(eq|match|filter|or)\\([^\\n;]{0,140}['\"]$column['\"]",
        caseSensitive: false,
      );
      if (pattern.hasMatch(snippet)) {
        return true;
      }

      final orStringPattern = RegExp(
        "\\.or\\(\\s*['\"][^'\"]*\\b$column\\.eq\\b",
        caseSensitive: false,
      );
      if (orStringPattern.hasMatch(snippet)) {
        return true;
      }
    }

    return false;
  }

  static bool _usesClientProvidedUserId(
    String snippet,
    String localContext,
    Set<String> expectedColumns,
  ) {
    const suspiciousValuePattern =
        r'''widget\.(userId|profileId|ownerId)|args\.(userId|profileId|ownerId)|route(?:Args|Parameters|Params)?\.(userId|profileId|ownerId)|params\[['"](userId|profileId|ownerId)['"]\]|queryParameters\[['"](userId|profileId|ownerId)['"]\]|pathParameters\[['"](userId|profileId|ownerId)['"]\]|state\.(extra|pathParameters|uri\.queryParameters)[^,\n;)]*(userId|profileId|ownerId)|request\.[a-zA-Z0-9_]*(id|Id)\b|selectedUserId|targetUserId|routeUserId|suppliedUserId|providedUserId|incomingUserId|passedUserId''';
    const variableNames = [
      'userId',
      'profileId',
      'ownerId',
      'suppliedUserId',
      'providedUserId',
      'incomingUserId',
      'passedUserId',
    ];
    for (final column in expectedColumns) {
      final filterPattern = RegExp(
        "\\.(eq|match|filter)\\([^\\n;]{0,120}['\"]$column['\"][^\\n;]{0,160}$suspiciousValuePattern",
        caseSensitive: false,
      );
      if (filterPattern.hasMatch(snippet)) {
        return true;
      }

      final fallbackPattern = RegExp(
        '\\.(eq|match|filter)\\([^\\n;]{0,160}\\?\\?\\s*(?:$suspiciousValuePattern|userId|profileId|ownerId)\\b',
        caseSensitive: false,
      );
      if (fallbackPattern.hasMatch(snippet)) {
        return true;
      }

      final assignmentPattern = RegExp(
        "['\"]$column['\"]\\s*:\\s*$suspiciousValuePattern",
        caseSensitive: false,
      );
      if (assignmentPattern.hasMatch(snippet)) {
        return true;
      }

      for (final variableName in variableNames) {
        final snippetVariablePattern = RegExp(
          "\\.(eq|match|filter)\\([^\\n;]{0,120}['\"]$column['\"][^\\n;]{0,80}\\b$variableName\\b",
          caseSensitive: false,
        );
        if (!snippetVariablePattern.hasMatch(snippet)) {
          continue;
        }

        final assignments = RegExp(
          '\\b$variableName\\b\\s*=\\s*([^\\n;]+)',
          caseSensitive: false,
        ).allMatches(localContext).toList();
        if (assignments.isEmpty) {
          continue;
        }

        final latestValue = assignments.last.group(1)!.trim();
        if (RegExp(
          r'''currentUser|auth\.user|auth\.currentUser''',
          caseSensitive: false,
        ).hasMatch(latestValue)) {
          return false;
        }

        if (RegExp(
          r'''widget\.|args\.|route|params\[|queryParameters\[|pathParameters\[|state\.|request\.|['"]''',
          caseSensitive: false,
        ).hasMatch(latestValue)) {
          return true;
        }
      }
    }

    return false;
  }

  static bool _hasNearbyValidationHelperCall(ScannedFile file, int line) {
    final helperCallPattern = RegExp(
      r'''\b(?:validate|verify|ensure|guard|check|sanitize|assert)(?:Valid)?[_A-Za-z0-9]*(?:upload|file|image|avatar|media|attachment)[_A-Za-z0-9]*\s*\(''',
      caseSensitive: false,
    );
    final functionDefinitionPattern = RegExp(
      r'''^\s*(?:[\w<>,?]+\s+)+[A-Za-z_][A-Za-z0-9_]*\s*\([^;]*\)\s*(?:async\s*)?(?:\{|=>)''',
    );

    final startLine = (line - 12).clamp(1, file.lines.length);
    for (var index = startLine - 1; index < line; index++) {
      final lineText = file.lines[index].trimRight();
      if (!helperCallPattern.hasMatch(lineText)) {
        continue;
      }
      if (functionDefinitionPattern.hasMatch(lineText.trimLeft())) {
        continue;
      }
      return true;
    }

    return false;
  }

  static String _stripQuotes(String value) {
    if (value.length < 2) {
      return value;
    }

    final quote = value[0];
    if ((quote == '"' || quote == "'") && value.endsWith(quote)) {
      return value.substring(1, value.length - 1);
    }

    return value;
  }

  /// Maximum in-memory size for a single scanned file.
  ///
  /// Beyond this size the file is skipped entirely (empty content). The cap
  /// protects against pathological inputs — bundled minified JS, multi-MB
  /// SVGs embedded in Dart, vendored data blobs — that would otherwise
  /// produce O(n²) scans or outright exhaust memory. 2 MiB is comfortably
  /// above any hand-authored source file.
  static const int _maxFileBytes = 2 * 1024 * 1024;

  static String _readTextFile(File file) {
    try {
      // Stat the file first so we can bail on large inputs without reading
      // them. `lengthSync()` is cheap on all supported platforms.
      final size = file.lengthSync();
      if (size > _maxFileBytes) {
        return '';
      }

      var bytes = file.readAsBytesSync();

      // Skip files that declare a non-UTF-8 text encoding via BOM. We do not
      // decode UTF-16 / UTF-32 at all — passing those bytes through
      // `utf8.decode(allowMalformed: true)` produces a stream of replacement
      // chars that break every offset calculation downstream.
      if (_hasUtf16OrUtf32Bom(bytes)) {
        return '';
      }

      // Strip UTF-8 BOM (EF BB BF) if present — prevents offset miscalculation.
      if (bytes.length >= 3 &&
          bytes[0] == 0xEF &&
          bytes[1] == 0xBB &&
          bytes[2] == 0xBF) {
        bytes = bytes.sublist(3);
      }

      var content = utf8.decode(bytes, allowMalformed: true);

      // Normalize CRLF → LF so line splitting works consistently across
      // platforms and line-offset calculations are correct.
      content = content.replaceAll('\r\n', '\n').replaceAll('\r', '\n');

      return content;
    } on FileSystemException {
      return '';
    }
  }

  static bool _hasUtf16OrUtf32Bom(List<int> bytes) {
    if (bytes.length >= 4) {
      // UTF-32 BE: 00 00 FE FF
      if (bytes[0] == 0x00 &&
          bytes[1] == 0x00 &&
          bytes[2] == 0xFE &&
          bytes[3] == 0xFF) {
        return true;
      }
      // UTF-32 LE: FF FE 00 00
      if (bytes[0] == 0xFF &&
          bytes[1] == 0xFE &&
          bytes[2] == 0x00 &&
          bytes[3] == 0x00) {
        return true;
      }
    }
    if (bytes.length >= 2) {
      // UTF-16 BE: FE FF
      if (bytes[0] == 0xFE && bytes[1] == 0xFF) return true;
      // UTF-16 LE: FF FE (but only if not UTF-32 LE, checked above)
      if (bytes[0] == 0xFF && bytes[1] == 0xFE) return true;
    }
    return false;
  }

  static int _pathDepth(String path) => normalizePath(
    path,
  ).split('/').where((segment) => segment.isNotEmpty).length;

  bool _fileContains(ScannedFile? file, RegExp pattern) {
    if (file == null) {
      return false;
    }

    return pattern.hasMatch(file.content);
  }

  bool _filesContain(
    Iterable<ScannedFile> candidateFiles,
    RegExp pattern, {
    bool stripDartComments = false,
  }) {
    for (final file in candidateFiles) {
      final content = stripDartComments
          ? _stripDartComments(file.content)
          : file.content;
      if (pattern.hasMatch(content)) {
        return true;
      }
    }
    return false;
  }

  bool _looksLikeSupabaseFile(ScannedFile file) =>
      _supabaseUsagePattern.hasMatch(file.content);

  static final _supabaseUsagePattern = RegExp(
    r'''package:supabase(?:_flutter)?/|\bSupabaseClient\b|\bSupabase\.(instance|initialize)\b|\bsupabase\.(from|storage|auth|rpc)\b|\.storage\.from\(|\.auth\.(currentUser|currentSession)\b''',
    caseSensitive: false,
  );

  // Strong DDL evidence: actual policy creation or RLS enablement.
  static final _strongRlsPattern = RegExp(
    r'''create\s+policy\b|enable\s+row\s+level\s+security\b''',
    caseSensitive: false,
  );

  // Weak textual evidence: mentions of RLS or auth.uid without DDL.
  static final _weakRlsPattern = RegExp(
    r'''row\s+level\s+security|\brls\b|auth\.uid\(\)''',
    caseSensitive: false,
  );

  static final _authUidPattern = RegExp(
    r'''auth\.uid\(\)''',
    caseSensitive: false,
  );

  bool _gitignorePatternMatches({
    required String pattern,
    required String targetPath,
    required String gitignoreDirectory,
  }) {
    final normalizedTargetPath = normalizePath(targetPath);
    var normalizedPattern = normalizePath(pattern);
    if (normalizedPattern.endsWith('/')) {
      normalizedPattern = normalizedPattern.substring(
        0,
        normalizedPattern.length - 1,
      );
    }
    if (normalizedPattern.isEmpty) {
      return false;
    }

    final anchoredToRoot = normalizedPattern.startsWith('/');
    if (anchoredToRoot) {
      normalizedPattern = normalizedPattern.substring(1);
    }

    if (!normalizedPattern.contains('/')) {
      if (!anchoredToRoot && gitignoreDirectory != '.') {
        final prefix = '$gitignoreDirectory/';
        if (!normalizedTargetPath.startsWith(prefix)) {
          return false;
        }
      }

      final candidate = anchoredToRoot
          ? normalizedTargetPath
          : basename(normalizedTargetPath);
      return _globMatches(candidate, normalizedPattern);
    }

    String candidatePath;
    if (anchoredToRoot || gitignoreDirectory == '.') {
      candidatePath = normalizedTargetPath;
    } else {
      final prefix = '$gitignoreDirectory/';
      if (!normalizedTargetPath.startsWith(prefix)) {
        return false;
      }
      candidatePath = normalizedTargetPath.substring(prefix.length);
    }

    return _globMatches(candidatePath, normalizedPattern);
  }

  bool _globMatches(String value, String pattern) {
    final buffer = StringBuffer('^');
    for (var index = 0; index < pattern.length; index++) {
      final char = pattern[index];
      if (char == '*') {
        final nextIsStar =
            index + 1 < pattern.length && pattern[index + 1] == '*';
        if (nextIsStar) {
          buffer.write('.*');
          index++;
        } else {
          buffer.write('[^/]*');
        }
        continue;
      }

      if (char == '?') {
        buffer.write('[^/]');
        continue;
      }

      buffer.write(RegExp.escape(char));
    }
    buffer.write(r'$');
    return RegExp(buffer.toString()).hasMatch(value);
  }

  static bool _isTestLikePath(String path) {
    return path.startsWith('test/') ||
        path.startsWith('integration_test/') ||
        path.startsWith('example/') ||
        path.contains('/test/') ||
        path.contains('/integration_test/') ||
        path.contains('/example/');
  }

  /// Returns true for auto-generated files that should be excluded from
  /// security scanning (high false-positive rate, not human-authored).
  static bool _isGeneratedCode(ScannedFile file) {
    final name = file.name;

    // Common Dart codegen suffixes.
    if (name.endsWith('.g.dart') ||
        name.endsWith('.freezed.dart') ||
        name.endsWith('.gen.dart') ||
        name.endsWith('.mocks.dart') ||
        name.endsWith('.gr.dart') ||
        name.endsWith('.pb.dart') ||
        name.endsWith('.pbenum.dart') ||
        name.endsWith('.pbjson.dart') ||
        name.endsWith('.pbserver.dart') ||
        name.endsWith('.chopper.dart') ||
        name.endsWith('.retrofit.dart') ||
        name.endsWith('.swagger.dart') ||
        name.endsWith('.openapi.dart') ||
        name.endsWith('.config.dart') && name.contains('router')) {
      return true;
    }

    // FFI / package:ffigen output — e.g. `pedometer_bindings_generated.dart`,
    // `foo_generated_bindings.dart`. This single pattern is what prevents
    // FFI-heavy repos (flutter/samples) from dumping thousands of findings.
    if (name.endsWith('_bindings_generated.dart') ||
        name.endsWith('_generated_bindings.dart') ||
        name.endsWith('_bindings.dart') && name.contains('generated') ||
        name.endsWith('.ffi.dart')) {
      return true;
    }

    // Check the first few lines for generated-code header markers.
    // These cover the markers emitted by build_runner, ffigen, protoc,
    // openapi-generator, swagger-dart-code-generator, freezed, and others.
    final checkLines = file.lines.length < 8 ? file.lines.length : 8;
    for (var i = 0; i < checkLines; i++) {
      final line = file.lines[i];
      if (line.contains('GENERATED CODE') ||
          line.contains('GENERATED FILE') ||
          line.contains('AUTO-GENERATED') ||
          line.contains('AUTOGENERATED') ||
          line.contains('DO NOT MODIFY') ||
          line.contains('DO NOT EDIT') ||
          line.contains('@generated')) {
        return true;
      }
    }
    return false;
  }
}

class EnvEntry {
  const EnvEntry({
    required this.key,
    required this.value,
    required this.file,
    required this.line,
  });

  final String key;
  final String value;
  final ScannedFile file;
  final int line;
}

class TableAccess {
  const TableAccess({
    required this.table,
    required this.operation,
    required this.file,
    required this.line,
    required this.snippet,
    required this.localContext,
    required this.hasOwnershipFilter,
    required this.usesClientProvidedUserId,
    required this.referencesCurrentUser,
  });

  final String table;
  final String operation;
  final ScannedFile file;
  final int line;
  final String snippet;
  final String localContext;
  final bool hasOwnershipFilter;
  final bool usesClientProvidedUserId;
  final bool referencesCurrentUser;
}

class StorageBucketUse {
  const StorageBucketUse({
    required this.bucketName,
    required this.operation,
    required this.file,
    required this.line,
    this.pathHasUserIdPattern = false,
    this.pathHasSensitiveContext = false,
  });

  final String bucketName;
  final String operation;
  final ScannedFile file;
  final int line;

  /// True when the upload path string looks like it contains a user identifier
  /// (e.g. `avatars/$userId.png`, `users/${user.id}/photo.jpg`).
  final bool pathHasUserIdPattern;

  /// True when the upload path string contains sensitive keywords
  /// (e.g. avatar, profile, user, private)
  final bool pathHasSensitiveContext;
}

class UploadCall {
  const UploadCall({
    required this.file,
    required this.line,
    required this.hasTypeValidation,
    required this.hasSizeValidation,
    required this.hasValidationHelper,
  });

  final ScannedFile file;
  final int line;
  final bool hasTypeValidation;
  final bool hasSizeValidation;
  final bool hasValidationHelper;
}

class Location {
  const Location({required this.file, required this.line});

  final ScannedFile file;
  final int line;
}

Set<String> ownerColumnsForTable(String tableName) {
  final normalized = tableName.toLowerCase();
  const mapping = <String, Set<String>>{
    'profiles': {'id'},
    'users': {'id'},
    'posts': {'user_id'},
    'messages': {'sender_id', 'receiver_id'},
    'todos': {'user_id'},
    'notes': {'user_id'},
    'orders': {'user_id'},
    'comments': {'user_id'},
  };

  if (mapping.containsKey(normalized)) {
    return mapping[normalized]!;
  }

  // Heuristic fallback for unknown tables: use common ownership column names.
  // This enables the scanner to flag unfiltered queries on ANY table, not just
  // the 8 hardcoded ones.
  return const {'user_id', 'owner_id', 'created_by', 'author_id'};
}

String? suggestedPolicyForTable(String tableName) {
  final normalized = tableName.toLowerCase();
  switch (normalized) {
    case 'profiles':
    case 'users':
      return 'auth.uid() = id';
    case 'posts':
    case 'todos':
    case 'notes':
    case 'orders':
    case 'comments':
      return 'auth.uid() = user_id';
    case 'messages':
      return 'auth.uid() = sender_id OR auth.uid() = receiver_id';
    default:
      return null;
  }
}
