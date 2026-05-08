#!/usr/bin/env bash
# bootstrap.sh — one-shot environment setup for contributors.
#
# Detects what's missing for building / running the project end-to-end
# (Rust engine + TS extension + Dart scanner) and either installs it or
# emits a precise install command the user can copy.
#
# Idempotent — safe to run repeatedly. Exits 0 only when every required
# tool is present at the required minimum version.
#
# Usage:
#   ./scripts/bootstrap.sh                  # interactive: prompts before installing
#   ./scripts/bootstrap.sh --yes            # non-interactive: installs without asking
#   ./scripts/bootstrap.sh --check          # check-only, never install (CI mode)

set -euo pipefail

# ---- arg parsing ------------------------------------------------------------

ASSUME_YES=false
CHECK_ONLY=false
for arg in "$@"; do
  case "$arg" in
    --yes|-y) ASSUME_YES=true ;;
    --check)  CHECK_ONLY=true ;;
    --help|-h)
      sed -n '2,15p' "$0"
      exit 0
      ;;
    *)
      echo "unknown arg: $arg" >&2
      exit 2
      ;;
  esac
done

# ---- pretty printing --------------------------------------------------------

if [ -t 1 ]; then
  RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
  BLUE=$'\033[34m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; RESET=''
fi

ok()      { printf '  %s✓%s %s\n'   "$GREEN" "$RESET" "$1"; }
warn()    { printf '  %s!%s %s\n'   "$YELLOW" "$RESET" "$1"; }
err()     { printf '  %s✗%s %s\n'   "$RED" "$RESET" "$1"; }
section() { printf '\n%s%s%s\n' "$BOLD" "$1" "$RESET"; }
hint()    { printf '    %s→%s %s\n' "$BLUE" "$RESET" "$1"; }

# ---- prompt helper ----------------------------------------------------------

prompt_install() {
  local tool="$1"
  local cmd="$2"
  if $CHECK_ONLY; then
    err "$tool missing — would install with:"
    hint "$cmd"
    return 1
  fi
  if $ASSUME_YES; then
    echo "Installing $tool: $cmd"
    eval "$cmd"
    return $?
  fi
  printf '\n  Install %s now? [Y/n] ' "$tool"
  read -r reply </dev/tty
  case "$reply" in
    n|N|no|NO) return 1 ;;
    *) eval "$cmd"; return $? ;;
  esac
}

# ---- version checks ---------------------------------------------------------

check_min_version() {
  # check_min_version "found" "required"  → returns 0 if found ≥ required
  local found="$1" required="$2"
  printf '%s\n%s\n' "$required" "$found" | sort -V -C
}

REQUIRED_RUST="1.85.0"
REQUIRED_NODE="18.0.0"
REQUIRED_DART="3.0.0"

MISSING=0

# ---- Rust toolchain ---------------------------------------------------------

section "Rust toolchain (required for the analysis engine)"

# Source cargo env if rustup was installed but the current shell hasn't
# picked it up yet (common right after first install).
if [ -f "$HOME/.cargo/env" ] && ! command -v cargo >/dev/null 2>&1; then
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

if command -v cargo >/dev/null 2>&1; then
  rust_version=$(rustc --version 2>/dev/null | awk '{print $2}')
  if check_min_version "$rust_version" "$REQUIRED_RUST"; then
    ok "rustc $rust_version (≥ $REQUIRED_RUST)"
  else
    err "rustc $rust_version is too old; need ≥ $REQUIRED_RUST"
    if prompt_install "rustup update" "rustup install $REQUIRED_RUST && rustup default $REQUIRED_RUST"; then
      ok "rustc updated"
    else
      MISSING=$((MISSING + 1))
    fi
  fi
else
  err "rustup / cargo not found"
  hint "The Rust analysis engine (engine/) cannot build or run without it."
  hint "End users of the prebuilt VS Code extension don't need this — it's"
  hint "for contributors and for building the engine binary from source."
  install_cmd="curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain $REQUIRED_RUST"
  if prompt_install "rustup + Rust $REQUIRED_RUST" "$install_cmd"; then
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
    ok "rustup installed"
  else
    MISSING=$((MISSING + 1))
    hint "Manual install: $install_cmd"
    hint "Then: source \$HOME/.cargo/env"
  fi
fi

# ---- system libs needed by --features full ---------------------------------

section "Optional system libs (needed only for --features full builds)"

case "$(uname -s)" in
  Darwin)
    if command -v brew >/dev/null 2>&1; then
      for pkg in cmake llvm rocksdb z3; do
        if brew list --formula "$pkg" >/dev/null 2>&1; then
          ok "brew: $pkg"
        else
          warn "brew: $pkg not installed"
          hint "brew install $pkg  (only required if building with --features full)"
        fi
      done
    else
      warn "Homebrew not detected; install from https://brew.sh if you need RocksDB/Z3."
    fi
    ;;
  Linux)
    for pkg in librocksdb-dev libz3-dev clang; do
      if dpkg -s "$pkg" >/dev/null 2>&1; then
        ok "apt: $pkg"
      else
        warn "apt: $pkg not installed"
        hint "sudo apt-get install -y $pkg  (only required if building with --features full)"
      fi
    done
    ;;
  *)
    warn "Non-Darwin/Linux platform; install RocksDB and Z3 manually if you need --features full."
    ;;
esac

# ---- Node.js ----------------------------------------------------------------

section "Node.js (required for the VS Code extension)"

if command -v node >/dev/null 2>&1; then
  node_version=$(node --version | sed 's/^v//')
  if check_min_version "$node_version" "$REQUIRED_NODE"; then
    ok "node $node_version (≥ $REQUIRED_NODE)"
  else
    err "node $node_version is too old; need ≥ $REQUIRED_NODE"
    hint "Install via https://nodejs.org or your package manager"
    MISSING=$((MISSING + 1))
  fi
else
  err "node not found"
  hint "Install from https://nodejs.org or via your package manager"
  hint "  macOS:  brew install node"
  hint "  Linux:  see https://nodejs.org/en/download/package-manager"
  MISSING=$((MISSING + 1))
fi

# ---- Dart -------------------------------------------------------------------

section "Dart (required for the lib/ scanner)"

if command -v dart >/dev/null 2>&1; then
  dart_version=$(dart --version 2>&1 | awk '{print $4}')
  if check_min_version "$dart_version" "$REQUIRED_DART"; then
    ok "dart $dart_version (≥ $REQUIRED_DART)"
  else
    err "dart $dart_version is too old; need ≥ $REQUIRED_DART"
    hint "Install Flutter (which bundles Dart) from https://flutter.dev"
    MISSING=$((MISSING + 1))
  fi
else
  err "dart not found"
  hint "Install Flutter (which bundles Dart) from https://flutter.dev"
  hint "  macOS:  brew install --cask flutter"
  hint "  Linux:  see https://docs.flutter.dev/get-started/install"
  MISSING=$((MISSING + 1))
fi

# ---- summary ----------------------------------------------------------------

section "Summary"

if [ "$MISSING" -eq 0 ]; then
  ok "All required tools present. You can build everything:"
  hint "Engine:    cd engine && cargo build --workspace --release"
  hint "Extension: cd vscode-extension && npm install && npm run compile"
  hint "Dart lib:  dart pub get && dart test"
  exit 0
else
  err "$MISSING required tool(s) missing. Install them and re-run this script."
  exit 1
fi
