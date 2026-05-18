#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/check-dev.sh [options]

Fast source-code drafting loop.

Options:
  -p, --package <name>   Limit to a package. May be repeated.
  --all-features         Enable all features.
  --no-default-features  Disable default features.
  --features <list>      Enable a comma-separated feature list.
  -h, --help             Show this help.

Default:
  cargo check --workspace --all-targets --keep-going

This script intentionally does not run tests, docs, coverage, loom, or mutants.
EOF
}

packages=()
cargo_args=(check --all-targets --keep-going)

while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--package)
      if [[ $# -lt 2 ]]; then
        echo "$1 requires a value" >&2
        exit 1
      fi
      packages+=("$2")
      shift 2
      ;;
    --all-features|--no-default-features)
      cargo_args+=("$1")
      shift
      ;;
    --features)
      if [[ $# -lt 2 ]]; then
        echo "--features requires a value" >&2
        exit 1
      fi
      cargo_args+=("--features" "$2")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ! -f Cargo.toml ]]; then
  echo "scripts/check-dev.sh must be run from the repository root after Cargo.toml exists." >&2
  exit 1
fi

if [[ "${#packages[@]}" -eq 0 ]]; then
  cargo_args+=("--workspace")
else
  for package in "${packages[@]}"; do
    cargo_args+=("-p" "$package")
  done
fi

echo "==> cargo ${cargo_args[*]}"
cargo "${cargo_args[@]}"
