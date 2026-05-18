#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/stress-mutants.sh [options]

Phase-closure mutation testing helper.

Options:
  -p, --package <name>   Limit mutation testing to a package. May be repeated.
  --smoke                Validate script/tool availability only.
  -h, --help             Show this help.

Default:
  cargo mutants --workspace

This script is explicitly excluded from scripts/check-dev.sh, check-test.sh,
and check.sh. It must be run only after normal fmt/check/clippy/doc/test/coverage
gates are green.
EOF
}

packages=()
smoke=0

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
    --smoke)
      smoke=1
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

if ! cargo mutants --version >/dev/null 2>&1; then
  if [[ "$smoke" -eq 1 ]]; then
    echo "cargo-mutants is not installed. Install before mutation gates with: cargo install cargo-mutants --locked"
    exit 0
  fi
  echo "cargo-mutants is required. Install with: cargo install cargo-mutants --locked" >&2
  exit 1
fi

if [[ "$smoke" -eq 1 ]]; then
  echo "stress-mutants smoke: $(cargo mutants --version)"
  exit 0
fi

if [[ ! -f Cargo.toml ]]; then
  echo "scripts/stress-mutants.sh must be run from the repository root after Cargo.toml exists." >&2
  exit 1
fi

mutants_args=(mutants)
if [[ "${#packages[@]}" -eq 0 ]]; then
  mutants_args+=(--workspace)
else
  for package in "${packages[@]}"; do
    mutants_args+=("--package" "$package")
  done
fi

echo "==> cargo ${mutants_args[*]}"
cargo "${mutants_args[@]}"
