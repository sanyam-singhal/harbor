#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/coverage-report.sh [options]

Default llvm-cov workflow for Harbor.

Options:
  -p, --package <name>   Limit coverage to a package. May be repeated.
  --workspace            Run against the full workspace. Default when no package is supplied.
  --all-features         Enable all features. Default when no feature flag is supplied.
  --no-default-features  Disable default features.
  --features <list>      Enable a comma-separated feature list.
  --output-dir <dir>     Coverage artifact directory. Default: .local/coverage
  -h, --help             Show this help.

Outputs:
  .local/coverage/summary.md
  .local/coverage/gate.txt
  .local/coverage/test-run.txt
  .local/coverage/text/coverage.txt
  .local/coverage/html/index.html
  .local/coverage/lcov.info
  .local/coverage/summary.json

The script runs tests once with cargo llvm-cov --no-report, then generates
all report formats from the saved coverage data.
EOF
}

packages=()
feature_args=()
output_dir=".local/coverage"

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
    --workspace)
      shift
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
    --output-dir)
      if [[ $# -lt 2 ]]; then
        echo "--output-dir requires a value" >&2
        exit 1
      fi
      output_dir="$2"
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
  echo "scripts/coverage-report.sh must be run from the repository root after Cargo.toml exists." >&2
  exit 1
fi

if ! cargo llvm-cov --version >/dev/null 2>&1; then
  echo "cargo-llvm-cov is required. Install with: cargo install cargo-llvm-cov --locked" >&2
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
    scope_args+=("--package" "$package")
  done
fi

report_scope_args=()
if [[ "${#packages[@]}" -gt 0 ]]; then
  for package in "${packages[@]}"; do
    report_scope_args+=("--package" "$package")
  done
fi

mkdir -p "$output_dir/text"

generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
summary_md="$output_dir/summary.md"
test_log="$output_dir/test-run.txt"
gate_log="$output_dir/gate.txt"
text_report="$output_dir/text/coverage.txt"
lcov_report="$output_dir/lcov.info"
json_report="$output_dir/summary.json"
html_dir="$output_dir/html"

write_summary() {
  local status="$1"
  cat > "$summary_md" <<EOF
# Coverage Report

Generated at: $generated_at

Status: $status

## Gate

- Line coverage: >= 90%
- Region coverage: >= 90%

## Scope

\`\`\`text
cargo llvm-cov ${scope_args[*]} ${feature_args[*]}
\`\`\`

## Artifacts

- Gate output: $gate_log
- Test run output: $test_log
- Text report: $text_report
- HTML report: $html_dir/index.html
- LCOV report: $lcov_report
- JSON summary: $json_report

## Gate Output Tail

\`\`\`text
EOF
  if [[ -f "$gate_log" ]]; then
    tail -n 80 "$gate_log" >> "$summary_md"
  else
    echo "Gate output was not generated." >> "$summary_md"
  fi
  cat >> "$summary_md" <<'EOF'
```
EOF
}

echo "==> cargo llvm-cov clean --workspace"
cargo llvm-cov clean --workspace

run_args=(llvm-cov "${scope_args[@]}" "${feature_args[@]}" --no-report)
echo "==> cargo ${run_args[*]}"
if ! cargo "${run_args[@]}" 2>&1 | tee "$test_log"; then
  write_summary "FAILED during coverage test run"
  exit 1
fi

echo "==> cargo llvm-cov report ${report_scope_args[*]} --text --output-path $text_report"
cargo llvm-cov report "${report_scope_args[@]}" --text --output-path "$text_report"

echo "==> cargo llvm-cov report ${report_scope_args[*]} --html --output-dir $output_dir"
cargo llvm-cov report "${report_scope_args[@]}" --html --output-dir "$output_dir"

echo "==> cargo llvm-cov report ${report_scope_args[*]} --lcov --output-path $lcov_report"
cargo llvm-cov report "${report_scope_args[@]}" --lcov --output-path "$lcov_report"

echo "==> cargo llvm-cov report ${report_scope_args[*]} --json --summary-only --output-path $json_report"
cargo llvm-cov report "${report_scope_args[@]}" --json --summary-only --output-path "$json_report"

gate_args=(llvm-cov report "${report_scope_args[@]}" --fail-under-lines 90 --fail-under-regions 90)
echo "==> cargo ${gate_args[*]}"
set +e
cargo "${gate_args[@]}" 2>&1 | tee "$gate_log"
gate_status="${PIPESTATUS[0]}"
set -e

if [[ "$gate_status" -eq 0 ]]; then
  write_summary "PASSED"
else
  write_summary "FAILED coverage gate"
fi

echo "Coverage markdown: $summary_md"
exit "$gate_status"
