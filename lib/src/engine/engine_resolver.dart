// Locates the prebuilt `engine-cli` binary, or surfaces a precise
// install hint when it can't be found.
//
// This file is the canonical "find the engine" logic shared between the
// Dart scanner (`lib/src/scanner.dart`) and any external Dart caller. The
// VS Code extension has its own resolver in
// `vscode-extension/src/scanner/engineResolver.ts` that mirrors this one.
//
// Search order, first hit wins:
//   1. `ENGINE_CLI` environment variable (full path).
//   2. `<package>/bin/engine-cli-<platform>-<arch>` — bundled with the
//      published Dart pub package.
//   3. `engine/target/release/engine-cli` relative to repo root — for
//      developers running from a checked-out repo.
//   4. `/usr/local/bin/engine-cli` — for users who installed it globally.
//   5. `engine-cli` on `$PATH` — last-resort lookup.

import 'dart:io';

class EngineResolution {
  const EngineResolution.found(this.path)
      : status = EngineStatus.found,
        installHint = null;

  const EngineResolution.missing(this.installHint)
      : status = EngineStatus.missing,
        path = null;

  final EngineStatus status;
  final String? path;
  final String? installHint;
}

enum EngineStatus { found, missing }

class EngineResolver {
  /// Walk the candidate locations and return the first one that exists.
  /// When nothing matches, return a `missing` resolution carrying a
  /// platform-specific install hint the caller can show the user.
  static EngineResolution resolve({String? repoRoot}) {
    for (final candidate in _candidates(repoRoot: repoRoot)) {
      if (File(candidate).existsSync()) {
        return EngineResolution.found(candidate);
      }
    }
    return EngineResolution.missing(_installHint());
  }

  static Iterable<String> _candidates({String? repoRoot}) sync* {
    final envOverride = Platform.environment['ENGINE_CLI'];
    if (envOverride != null && envOverride.isNotEmpty) {
      yield envOverride;
    }

    // Bundled with the package.
    yield Platform.script
        .resolve('../bin/engine-cli-${_platformKey()}')
        .toFilePath();

    // Repo checkout: `engine/target/release/engine-cli`.
    if (repoRoot != null) {
      yield '$repoRoot/engine/target/release/engine-cli';
    }

    // Globally installed.
    yield '/usr/local/bin/engine-cli';
    yield '/opt/homebrew/bin/engine-cli';
  }

  /// `darwin-arm64` / `darwin-x64` / `linux-x64` / `win-x64.exe`.
  static String _platformKey() {
    final platform = Platform.operatingSystem;
    final arch = _archHint();
    if (platform == 'windows') return 'win-x64.exe';
    if (platform == 'macos') return 'darwin-$arch';
    return 'linux-$arch';
  }

  static String _archHint() {
    // Dart doesn't expose the running CPU architecture directly. Best-effort
    // by reading `Platform.version`, which contains `arm64` / `x64` on macOS
    // and `x64_64` / `aarch64` on Linux. Defaults to `x64` if ambiguous.
    final v = Platform.version.toLowerCase();
    if (v.contains('arm64') || v.contains('aarch64')) return 'arm64';
    return 'x64';
  }

  static String _installHint() {
    final platform = Platform.operatingSystem;
    final repoUrl = 'https://github.com/icyarcanine/flutter-security-scanner';
    final lines = <String>[
      'The Rust analysis kernel binary `engine-cli` was not found.',
      '',
      'Without it, the Dart scanner falls back to its built-in pattern-matching',
      'rules only — IFDS taint analysis (the high-confidence findings) is skipped.',
      '',
      'To install:',
      '',
      '  Option A — install Rust and build from source:',
      '    curl --proto \'=https\' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.85.0',
      '    source \$HOME/.cargo/env',
      '    git clone $repoUrl',
      '    cd flutter-security-scanner/engine && cargo build --release -p engine-cli',
      '    export ENGINE_CLI=\$(pwd)/target/release/engine-cli',
      '',
      '  Option B — download a prebuilt binary:',
      '    See $repoUrl/releases',
      '    Move it to /usr/local/bin/engine-cli and chmod +x',
    ];
    if (platform == 'macos') {
      lines.add('');
      lines.add('  Option C — bootstrap script (handles everything):');
      lines
          .add('    bash <(curl -fsSL $repoUrl/raw/main/scripts/bootstrap.sh)');
    }
    lines.add('');
    lines.add('Re-run the scanner after installation.');
    return lines.join('\n');
  }
}
