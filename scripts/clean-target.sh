#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/clean-target.sh

Optional phase-closure disk hygiene helper.

Run only after the phase gate and stress helpers are complete. This removes
Cargo build artifacts while preserving git-ignored local reports such as
.local/coverage/summary.md.
EOF
}

if [[ "${1-}" == "--help" || "${1-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ ! -f Cargo.toml ]]; then
  echo "scripts/clean-target.sh must be run from the repository root after Cargo.toml exists." >&2
  exit 1
fi

echo "==> cargo llvm-cov clean --workspace"
cargo llvm-cov clean --workspace

echo "==> cargo clean"
cargo clean
