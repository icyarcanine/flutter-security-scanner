/**
 * Locates the prebuilt `engine-cli` binary, or surfaces a precise
 * install hint when it can't be found.
 *
 * Mirror of `lib/src/engine/engine_resolver.dart` for the TS side. Search
 * order, first hit wins:
 *
 *   1. `ENGINE_CLI` environment variable (full path).
 *   2. `<extension>/bin/engine-cli-<platform>-<arch>` — bundled with the .vsix.
 *   3. `<workspace>/engine/target/release/engine-cli` — for developers
 *      running from a checked-out repo.
 *   4. `/usr/local/bin/engine-cli` and `/opt/homebrew/bin/engine-cli` —
 *      for users who installed it globally.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

export interface EngineResolution {
  status: 'found' | 'missing';
  /** Absolute path to the binary; defined iff `status === 'found'`. */
  path?: string;
  /** Human-readable install hint; defined iff `status === 'missing'`. */
  installHint?: string;
}

export function resolveEngineBinary(opts: {
  extensionPath: string;
  workspaceRoot?: string;
}): EngineResolution {
  const candidates = [...iterCandidates(opts)];
  for (const p of candidates) {
    if (fs.existsSync(p)) {
      return { status: 'found', path: p };
    }
  }
  return { status: 'missing', installHint: buildInstallHint() };
}

function* iterCandidates(opts: {
  extensionPath: string;
  workspaceRoot?: string;
}): Iterable<string> {
  const envOverride = process.env.ENGINE_CLI;
  if (envOverride) {
    yield envOverride;
  }

  // Bundled with the extension.
  yield path.join(opts.extensionPath, 'bin', `engine-cli-${platformKey()}`);

  // Repo checkout.
  if (opts.workspaceRoot) {
    yield path.join(opts.workspaceRoot, 'engine', 'target', 'release', 'engine-cli');
  }

  // Globally installed.
  yield '/usr/local/bin/engine-cli';
  yield '/opt/homebrew/bin/engine-cli';
}

/** `darwin-arm64` / `darwin-x64` / `linux-x64` / `win-x64.exe`. */
export function platformKey(): string {
  const platform = os.platform();
  const arch = os.arch();
  if (platform === 'win32') return 'win-x64.exe';
  if (platform === 'darwin') return `darwin-${arch === 'arm64' ? 'arm64' : 'x64'}`;
  return `linux-${arch === 'arm64' ? 'arm64' : 'x64'}`;
}

function buildInstallHint(): string {
  const repoUrl = 'https://github.com/dilpreet-s-sidhu/flutter-security-scanner';
  return [
    'The Rust analysis kernel binary `engine-cli` was not found.',
    '',
    'Without it, the scanner falls back to its built-in pattern-matching',
    'rules only — IFDS taint analysis (the high-confidence findings) is skipped.',
    '',
    'To install:',
    '',
    '  Option A — install Rust and build from source:',
    "    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.85.0",
    '    source $HOME/.cargo/env',
    `    git clone ${repoUrl}`,
    '    cd flutter-security-scanner/engine && cargo build --release -p engine-cli',
    '    export ENGINE_CLI=$(pwd)/target/release/engine-cli',
    '',
    '  Option B — bootstrap script (handles everything):',
    `    bash <(curl -fsSL ${repoUrl}/raw/main/scripts/bootstrap.sh)`,
    '',
    '  Option C — download a prebuilt binary:',
    `    See ${repoUrl}/releases`,
    '    Move it to /usr/local/bin/engine-cli and chmod +x',
    '',
    'Re-run the scanner after installation.',
  ].join('\n');
}
