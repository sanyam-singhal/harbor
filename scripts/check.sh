#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/check.sh

Phase-closure QA gate.

Runs the strict Rust gate:
  1. cargo fmt --all --check
  2. cargo check --workspace --all-targets --all-features --keep-going
  3. cargo clippy --workspace --all-targets --all-features -- -D warnings
  4. cargo doc --workspace --all-features --no-deps --document-private-items
  5. cargo test --workspace --all-features
  6. scripts/coverage-report.sh --workspace --all-features

Then runs smoke gates for non-Rust enclaves when present:
  7. root npm test
  8. ts-sdk npm test
  9. py-sdk uv run pytest
  10. ui npm test

Stress tools are intentionally excluded. Run scripts/stress-mutants.sh and,
for concurrency-critical crates, scripts/stress-loom.sh explicitly at phase
closure after this script is green.
EOF
}

if [[ "${1-}" == "--help" || "${1-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ ! -f Cargo.toml ]]; then
  echo "scripts/check.sh must be run from the repository root after Cargo.toml exists." >&2
  exit 1
fi

echo "==> cargo fmt --all --check"
cargo fmt --all --check

echo "==> cargo check --workspace --all-targets --all-features --keep-going"
cargo check --workspace --all-targets --all-features --keep-going

echo "==> cargo clippy --workspace --all-targets --all-features -- -D warnings"
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "==> cargo doc --workspace --all-features --no-deps --document-private-items"
previous_rustdocflags="${RUSTDOCFLAGS-__UNSET__}"
export RUSTDOCFLAGS="-D warnings ${RUSTDOCFLAGS-}"
trap 'if [[ "$previous_rustdocflags" == "__UNSET__" ]]; then unset RUSTDOCFLAGS; else export RUSTDOCFLAGS="$previous_rustdocflags"; fi' EXIT
cargo doc --workspace --all-features --no-deps --document-private-items

echo "==> cargo test --workspace --all-features"
cargo test --workspace --all-features

echo "==> scripts/coverage-report.sh --workspace --all-features"
scripts/coverage-report.sh --workspace --all-features

if [[ -f package.json ]]; then
  echo "==> root npm ci && npm test"
  npm ci
  npm test
fi

if [[ -f ts-sdk/package.json ]]; then
  echo "==> ts-sdk npm ci && npm test"
  (cd ts-sdk && npm ci && npm test)
fi

if [[ -f py-sdk/pyproject.toml ]]; then
  uv_bin="${UV_BIN:-uv}"
  if ! command -v "$uv_bin" >/dev/null 2>&1; then
    if [[ -x "$HOME/.local/bin/uv" ]]; then
      uv_bin="$HOME/.local/bin/uv"
    else
      echo "uv is required for py-sdk checks. Install with: curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
      exit 1
    fi
  fi

  echo "==> py-sdk uv sync --locked && uv run pytest"
  (cd py-sdk && "$uv_bin" sync --locked && "$uv_bin" run pytest)
fi

if [[ -f ui/package.json ]]; then
  echo "==> ui npm ci && npm test"
  (cd ui && npm ci && npm test)
fi
