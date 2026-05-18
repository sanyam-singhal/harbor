#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$script_dir/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: read-rust-slice.sh [options]

Read a precise Rust source slice as markdown.

Options:
  --package <name>       Search within one Rust package.
  --item <name>          Emit the declaration containing this item name.
  --impls                With --item, also emit impl blocks mentioning the item.
  --pattern <regex>      Emit grep-style matches with context.
  --context <lines>      Context lines for --pattern. Default: 8.
  --path <file>          Read one repository-relative file.
  --lines <start:end>    Emit an exact 1-based inclusive line range from --path.
  --include-tests        Include tests/, examples/, benches/, and #[cfg(test)] source.
  --list-packages        List available Rust packages and exit.
  --help                 Show this help message.

Examples:
  scripts/read-rust-slice.sh --package harbor-core --item EmailAddress
  scripts/read-rust-slice.sh --package harbor-core --item EmailAddress --impls
  scripts/read-rust-slice.sh --package harbor-core --pattern InvalidEmail --context 12
  scripts/read-rust-slice.sh --path crates/harbor-core/src/lib.rs --lines 1:80
EOF
}

package=""
item=""
pattern=""
context=8
path=""
line_range=""
include_tests=0
list_packages=0
include_impls=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --package)
      if [[ $# -lt 2 ]]; then
        echo "--package requires a value" >&2
        exit 1
      fi
      package="$2"
      shift 2
      ;;
    --item)
      if [[ $# -lt 2 ]]; then
        echo "--item requires a value" >&2
        exit 1
      fi
      item="$2"
      shift 2
      ;;
    --pattern)
      if [[ $# -lt 2 ]]; then
        echo "--pattern requires a value" >&2
        exit 1
      fi
      pattern="$2"
      shift 2
      ;;
    --impls)
      include_impls=1
      shift
      ;;
    --context)
      if [[ $# -lt 2 ]]; then
        echo "--context requires a value" >&2
        exit 1
      fi
      context="$2"
      shift 2
      ;;
    --path)
      if [[ $# -lt 2 ]]; then
        echo "--path requires a value" >&2
        exit 1
      fi
      path="$2"
      shift 2
      ;;
    --lines)
      if [[ $# -lt 2 ]]; then
        echo "--lines requires a value" >&2
        exit 1
      fi
      line_range="$2"
      shift 2
      ;;
    --include-tests)
      include_tests=1
      shift
      ;;
    --list-packages)
      list_packages=1
      shift
      ;;
    --help|-h)
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

find_packages() {
  find "$root" -mindepth 1 -maxdepth 4 -type f -name 'Cargo.toml' \
    -not -path '*/target/*' \
    -print \
    | LC_ALL=C sort
}

package_name_from_manifest() {
  local manifest_path="$1"
  awk '
    /^\[package\]/ { in_package = 1; next }
    /^\[/ && !/^\[package\]/ { in_package = 0 }
    in_package && /^[[:space:]]*name[[:space:]]*=/ {
      line = $0
      sub(/^[^"]*"/, "", line)
      sub(/".*$/, "", line)
      print line
      exit
    }
  ' "$manifest_path"
}

package_dir_from_manifest() {
  local manifest_path="$1"
  dirname "$manifest_path"
}

declare -a package_names=()
declare -a package_dirs=()

while IFS= read -r manifest; do
  package_name="$(package_name_from_manifest "$manifest")"
  if [[ -n "$package_name" ]]; then
    package_names+=("$package_name")
    package_dirs+=("$(package_dir_from_manifest "$manifest")")
  fi
done < <(find_packages)

if [[ "$list_packages" -eq 1 ]]; then
  printf '%s\n' "${package_names[@]}"
  exit 0
fi

package_dir_by_name() {
  local needle="$1"
  local i
  for i in "${!package_names[@]}"; do
    if [[ "${package_names[$i]}" == "$needle" ]]; then
      printf '%s\n' "${package_dirs[$i]}"
      return 0
    fi
  done
  return 1
}

emit_non_test_lines() {
  local source_path="$1"
  if [[ "$include_tests" -eq 1 ]]; then
    cat "$source_path"
    return 0
  fi

  awk '
    function brace_delta(line, opens, closes) {
      opens = gsub(/\{/, "{", line)
      closes = gsub(/\}/, "}", line)
      return opens - closes
    }
    BEGIN {
      pending_cfg_test_item = 0
      skipping_cfg_test_item = 0
      brace_depth = 0
    }
    /^[[:space:]]*#\[cfg\(test\)\]/ {
      pending_cfg_test_item = 1
      print ""
      next
    }
    {
      if (skipping_cfg_test_item) {
        brace_depth += brace_delta($0)
        if (brace_depth <= 0) {
          skipping_cfg_test_item = 0
          brace_depth = 0
        }
        print ""
        next
      }

      if (pending_cfg_test_item) {
        if ($0 ~ /\{/) {
          brace_depth = brace_delta($0)
          if (brace_depth > 0) {
            skipping_cfg_test_item = 1
          } else {
            brace_depth = 0
          }
          pending_cfg_test_item = 0
        } else if ($0 ~ /;/) {
          pending_cfg_test_item = 0
        }
        print ""
        next
      }

      print
    }
  ' "$source_path"
}

rust_files_for_package() {
  local package_dir="$1"
  local find_args=("$package_dir/src")

  if [[ "$include_tests" -eq 1 ]]; then
    find_args+=("$package_dir/tests" "$package_dir/examples" "$package_dir/benches")
  fi

  find "${find_args[@]}" -type f -name '*.rs' 2>/dev/null | LC_ALL=C sort
}

emit_file_range() {
  local source_path="$1"
  local range="$2"
  local start="${range%:*}"
  local end="${range#*:}"

  if [[ ! "$start" =~ ^[0-9]+$ || ! "$end" =~ ^[0-9]+$ || "$start" -gt "$end" ]]; then
    echo "--lines must be formatted as start:end with start <= end" >&2
    exit 1
  fi

  printf '### `%s:%s`\n\n' "${source_path#$root/}" "$range"
  printf '```rust\n'
  sed -n "${start},${end}p" "$source_path"
  printf '```\n'
}

emit_pattern_matches() {
  local regex="$1"
  shift
  local files=("$@")
  local relative_files=()
  local file

  printf '## Pattern `%s`\n\n' "$regex"
  for file in "${files[@]}"; do
    relative_files+=("${file#$root/}")
  done
  (cd "$root" && rg -n -C "$context" "$regex" "${relative_files[@]}") || true
}

emit_item_from_file() {
  local source_path="$1"
  local item_name="$2"
  local mode="$3"

  awk -v item="$item_name" -v rel="${source_path#$root/}" -v mode="$mode" '
    function brace_delta(line, opens, closes) {
      opens = gsub(/\{/, "{", line)
      closes = gsub(/\}/, "}", line)
      return opens - closes
    }
    function identifier_hit(line, before, after) {
      before = "(^|[^A-Za-z0-9_])"
      after = "([^A-Za-z0-9_]|$)"
      return line ~ before item after
    }
    function flush() {
      if (capturing) {
        printf "### `%s:%d`\n\n", rel, start_line
        printf "```rust\n"
        printf "%s", buffer
        printf "```\n\n"
      }
    }
    BEGIN {
      pending = ""
      pending_start = 0
    }
    {
      if (!capturing) {
        if ($0 ~ /^[[:space:]]*#\[/ || $0 ~ /^[[:space:]]*\/\/\// || $0 ~ /^[[:space:]]*$/) {
          if (pending == "") {
            pending_start = NR
          }
          pending = pending $0 "\n"
          next
        }

        declaration_match = (mode != "impl" && $0 ~ /^[[:space:]]*(pub[[:space:]]+)?(struct|enum|trait|type|fn|const)[[:space:]]+/ && identifier_hit($0))
        impl_match = (mode == "impl" && $0 ~ /^[[:space:]]*impl([^A-Za-z0-9_]|[[:space:]]|<)/ && identifier_hit($0))

        if (declaration_match || impl_match) {
          capturing = 1
          start_line = pending_start ? pending_start : NR
          buffer = pending $0 "\n"
          depth = brace_delta($0)
          saw_body = ($0 ~ /\{/)
          pending = ""
          pending_start = 0
          if ($0 ~ /;/ && depth == 0) {
            flush()
            found = 1
            capturing = 0
            if (mode != "impl") {
              exit
            }
            next
          }
          if (depth <= 0 && $0 ~ /\}/) {
            flush()
            found = 1
            capturing = 0
            if (mode != "impl") {
              exit
            }
            next
          }
          next
        }

        pending = ""
        pending_start = 0
        next
      }

      buffer = buffer $0 "\n"
      depth += brace_delta($0)
      if ($0 ~ /\{/) {
        saw_body = 1
      }
      if (saw_body && depth <= 0) {
        flush()
        found = 1
        capturing = 0
        if (mode != "impl") {
          exit
        }
      }
    }
    END {
      if (!found && capturing) {
        flush()
      }
    }
  ' "$source_path"
}

if [[ -n "$path" ]]; then
  source_path="$root/${path#./}"
  if [[ ! -f "$source_path" ]]; then
    echo "No such file: $path" >&2
    exit 1
  fi
  if [[ -z "$line_range" ]]; then
    echo "--path requires --lines" >&2
    exit 1
  fi
  printf '# Rust Slice\n\n'
  emit_file_range "$source_path" "$line_range"
  exit 0
fi

if [[ -z "$package" ]]; then
  echo "--package is required unless --path is supplied" >&2
  usage >&2
  exit 1
fi

package_dir="$(package_dir_by_name "$package")" || {
  echo "Unknown package: $package" >&2
  exit 1
}

mapfile -t rust_files < <(rust_files_for_package "$package_dir")

if [[ "${#rust_files[@]}" -eq 0 ]]; then
  echo "No Rust files found for package: $package" >&2
  exit 1
fi

printf '# Rust Slice: %s\n\n' "$package"

if [[ -n "$pattern" ]]; then
  emit_pattern_matches "$pattern" "${rust_files[@]}"
  exit 0
fi

if [[ -n "$item" ]]; then
  found=0
  for rust_file in "${rust_files[@]}"; do
    temp_file="$(mktemp)"
    emit_non_test_lines "$rust_file" > "$temp_file"
    if rg -q "^[[:space:]]*(pub[[:space:]]+)?(struct|enum|trait|type|fn|const)[[:space:]]+$item([^A-Za-z0-9_]|$)" "$temp_file"; then
      emit_item_from_file "$temp_file" "$item" "declaration" \
        | sed "s|### \`${temp_file}:|### \`${rust_file#$root/}:|"
      if [[ "$include_impls" -eq 1 ]]; then
        emit_item_from_file "$temp_file" "$item" "impl" \
          | sed "s|### \`${temp_file}:|### \`${rust_file#$root/}:|"
      fi
      found=1
      rm -f "$temp_file"
      break
    fi
    rm -f "$temp_file"
  done
  if [[ "$found" -eq 0 ]]; then
    printf '_No item named `%s` found._\n' "$item"
  fi
  exit 0
fi

echo "One of --item, --pattern, or --path --lines is required" >&2
usage >&2
exit 1
