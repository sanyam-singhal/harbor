#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/check-test.sh [options]

Red-team test loop after a source draft is coherent.

Options:
  -p, --package <name>   Limit to a package. May be repeated.
  --all-features         Enable all features. Default when no feature flag is supplied.
  --no-default-features  Disable default features.
  --features <list>      Enable a comma-separated feature list.
  --no-coverage          Run cargo test only.
  -h, --help             Show this help.

Default:
  cargo test --workspace --all-features
  scripts/coverage-report.sh --workspace --all-features

This script intentionally does not run fmt, clippy, docs, loom, or mutants.
EOF
}

packages=()
feature_args=()
coverage=1

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
      feature_args+=("$1")
      shift
      ;;
    --features)
      if [[ $# -lt 2 ]]; then
        echo "--features requires a value" >&2
        exit 1
      fi
      feature_args+=("--features" "$2")
      shift 2
      ;;
    --no-coverage)
      coverage=0
      shift
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
  echo "scripts/check-test.sh must be run from the repository root after Cargo.toml exists." >&2
  exit 1
fi

if [[ "${#feature_args[@]}" -eq 0 ]]; then
  feature_args=(--all-features)
fi

scope_args=()
if [[ "${#packages[@]}" -eq 0 ]]; then
  scope_args=(--workspace)
else
  for package in "${packages[@]}"; do
    scope_args+=("-p" "$package")
  done
fi

test_args=(test "${scope_args[@]}" "${feature_args[@]}")
echo "==> cargo ${test_args[*]}"
cargo "${test_args[@]}"

if [[ "$coverage" -eq 1 ]]; then
  echo "==> scripts/coverage-report.sh ${scope_args[*]} ${feature_args[*]}"
  scripts/coverage-report.sh "${scope_args[@]}" "${feature_args[@]}"
fi
