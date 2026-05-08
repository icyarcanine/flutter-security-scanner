#!/usr/bin/env bash
# bundle-engine.sh — copy / build engine-cli binaries into vscode-extension/bin/
# so they ship inside the published .vsix.
#
# Modes:
#   ./scripts/bundle-engine.sh           # build host target only (fast, default)
#   ./scripts/bundle-engine.sh --all     # build every supported triple (needs cross-toolchains)
#   ./scripts/bundle-engine.sh --target <triple>   # build one specific triple
#
# CI uses --all on a Linux runner where cross-compiling to darwin and Windows
# requires SDKs that aren't on a developer's machine; the GitHub Actions
# `release.yml` workflow runs each target on its native runner instead.

set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p bin

# triple → bin filename
declare -a TARGETS=(
  "aarch64-apple-darwin:engine-cli-darwin-arm64"
  "x86_64-apple-darwin:engine-cli-darwin-x64"
  "x86_64-unknown-linux-gnu:engine-cli-linux-x64"
)

mode="host"
single_target=""
case "${1:-}" in
  --all) mode="all" ;;
  --target) mode="single"; single_target="${2:-}"; ;;
  "") mode="host" ;;
  *) echo "unknown arg: $1" >&2; exit 2 ;;
esac

# Pick host target by uname.
host_target() {
  local sys arch
  sys=$(uname -s)
  arch=$(uname -m)
  case "$sys" in
    Darwin)
      [[ "$arch" == "arm64" ]] && echo "aarch64-apple-darwin" || echo "x86_64-apple-darwin"
      ;;
    Linux)
      echo "x86_64-unknown-linux-gnu"
      ;;
    *)
      echo "Unsupported host: $sys" >&2
      exit 1
      ;;
  esac
}

build_target() {
  local target="$1"
  local out_name="$2"
  echo "==> $target → bin/$out_name"
  (cd ../engine && cargo build --release --target "$target" -p engine-cli)
  cp "../engine/target/$target/release/engine-cli" "bin/$out_name"
}

case "$mode" in
  host)
    target=$(host_target)
    out_name=""
    for entry in "${TARGETS[@]}"; do
      IFS=':' read -r t n <<< "$entry"
      [[ "$t" == "$target" ]] && out_name="$n"
    done
    [[ -z "$out_name" ]] && { echo "no mapping for $target" >&2; exit 1; }
    build_target "$target" "$out_name"
    ;;
  all)
    for entry in "${TARGETS[@]}"; do
      IFS=':' read -r t n <<< "$entry"
      build_target "$t" "$n"
    done
    ;;
  single)
    out_name=""
    for entry in "${TARGETS[@]}"; do
      IFS=':' read -r t n <<< "$entry"
      [[ "$t" == "$single_target" ]] && out_name="$n"
    done
    [[ -z "$out_name" ]] && { echo "unknown target: $single_target" >&2; exit 2; }
    build_target "$single_target" "$out_name"
    ;;
esac

echo "Done. bin/ contents:"
ls -la bin/
