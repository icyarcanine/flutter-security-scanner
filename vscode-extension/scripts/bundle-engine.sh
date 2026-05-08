#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p bin

TARGETS=(
  "darwin-arm64:aarch64-apple-darwin"
  "darwin-x64:x86_64-apple-darwin"
  "linux-x64:x86_64-unknown-linux-gnu"
)

for entry in "${TARGETS[@]}"; do
  IFS=':' read -r name target <<< "$entry"
  echo "Building engine-cli for $target"
  (cd ../engine && cargo build --release --target "$target" -p engine-cli)
  cp "../engine/target/$target/release/engine-cli" "bin/engine-cli-$name"
done
