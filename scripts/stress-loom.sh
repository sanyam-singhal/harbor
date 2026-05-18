#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/stress-loom.sh [options]

Phase-closure concurrency stress helper.

Options:
  -p, --package <name>   Run loom tests for a package. May be repeated.
  --smoke                Only validate script/tooling shape; do not run cargo test.
  -h, --help             Show this help.

Convention:
  Concurrency-critical crates that need loom must expose an optional feature
  named "loom" and gate model tests behind that feature.

Default:
  If no package is supplied, the script scans crates/*/Cargo.toml for "loom"
  and runs those packages. If none are found, it exits successfully.

This script is explicitly excluded from scripts/check-dev.sh, check-test.sh,
and check.sh. Use only at phase closure after the normal gates are green.
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

if [[ "$smoke" -eq 1 ]]; then
  echo "stress-loom smoke: ok"
  exit 0
fi

if [[ ! -f Cargo.toml ]]; then
  echo "No Cargo.toml found; no loom stress tests to run yet."
  exit 0
fi

if [[ "${#packages[@]}" -eq 0 && -d crates ]]; then
  while IFS= read -r manifest; do
    package_name="$(awk '
      /^\[package\]/ { in_package = 1; next }
      /^\[/ && !/^\[package\]/ { in_package = 0 }
      in_package && /^[[:space:]]*name[[:space:]]*=/ {
        line = $0
        sub(/^[^"]*"/, "", line)
        sub(/".*$/, "", line)
        print line
        exit
      }
    ' "$manifest")"
    if [[ -n "$package_name" ]]; then
      packages+=("$package_name")
    fi
  done < <(grep -RIl 'loom' crates/*/Cargo.toml 2>/dev/null | LC_ALL=C sort)
fi

if [[ "${#packages[@]}" -eq 0 ]]; then
  echo "No loom-enabled crates detected."
  exit 0
fi

for package in "${packages[@]}"; do
  echo "==> RUSTFLAGS=\"${RUSTFLAGS-} --cfg loom\" cargo test -p $package --features loom"
  RUSTFLAGS="${RUSTFLAGS-} --cfg loom" cargo test -p "$package" --features loom
done
