#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$script_dir/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: count-lines.sh [options]

Options:
  --package <name>     Limit output to a Rust package. May be repeated.
  --by-module          Emit a module-level breakdown. Requires exactly one --package.
  --list-packages      List available Rust packages and exit.
  --list-modules       List module names for the selected package and exit.
  --help               Show this help message.

Notes:
  - Package totals include Rust files under src/, tests/, examples/, and benches/.
  - Module mode groups src/ files by top-level module, plus pseudo-modules:
      lib, main, bin, tests, examples, benches
  - Source/test split is an estimate. Inline #[cfg(test)] blocks are counted as tests.
EOF
}

selected_packages=()
list_packages=0
list_modules=0
by_module=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --package)
      if [[ $# -lt 2 ]]; then
        echo "--package requires a value" >&2
        exit 1
      fi
      selected_packages+=("$2")
      shift 2
      ;;
    --by-module)
      by_module=1
      shift
      ;;
    --list-packages)
      list_packages=1
      shift
      ;;
    --list-modules)
      list_modules=1
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

declare -a package_manifests=()
declare -a package_names=()
declare -a package_dirs=()

while IFS= read -r manifest; do
  package_name="$(package_name_from_manifest "$manifest")"
  if [[ -n "$package_name" ]]; then
    package_manifests+=("$manifest")
    package_names+=("$package_name")
    package_dirs+=("$(package_dir_from_manifest "$manifest")")
  fi
done < <(find_packages)

if [[ "${#package_names[@]}" -eq 0 ]]; then
  echo "No Rust packages found under $root" >&2
  exit 1
fi

if [[ "$list_packages" -eq 1 ]]; then
  printf '%s\n' "${package_names[@]}"
  exit 0
fi

package_index_by_name() {
  local needle="$1"
  local i
  for i in "${!package_names[@]}"; do
    if [[ "${package_names[$i]}" == "$needle" ]]; then
      printf '%s\n' "$i"
      return 0
    fi
  done
  return 1
}

if [[ "${#selected_packages[@]}" -eq 0 ]]; then
  selected_packages=("${package_names[@]}")
fi

list_package_modules() {
  local package_dir="$1"
  local src_dir="$package_dir/src"

  if [[ ! -d "$src_dir" ]]; then
    return 0
  fi

  {
    find "$src_dir" -mindepth 1 -maxdepth 1 -type d -print \
      | xargs -r -n1 basename

    find "$src_dir" -mindepth 1 -maxdepth 1 -type f -name '*.rs' -print \
      | while IFS= read -r path; do
          local name
          name="$(basename "$path" .rs)"
          case "$name" in
            lib|main)
              printf '%s\n' "$name"
              ;;
          esac
        done

    for pseudo_module in tests examples benches; do
      if [[ -d "$package_dir/$pseudo_module" ]]; then
        printf '%s\n' "$pseudo_module"
      fi
    done
  } | LC_ALL=C sort -u
}

if [[ "$list_modules" -eq 1 ]]; then
  if [[ "${#selected_packages[@]}" -ne 1 ]]; then
    echo "--list-modules requires exactly one --package" >&2
    exit 1
  fi
  package_idx="$(package_index_by_name "${selected_packages[0]}")" || {
    echo "Unknown package: ${selected_packages[0]}" >&2
    exit 1
  }
  list_package_modules "${package_dirs[$package_idx]}"
  exit 0
fi

if [[ "$by_module" -eq 1 && "${#selected_packages[@]}" -ne 1 ]]; then
  echo "--by-module requires exactly one --package" >&2
  exit 1
fi

count_file_lines() {
  local path="$1"
  local base_name

  base_name="$(basename "$path")"
  if [[ "$path" == *"/tests/"* || "$base_name" == "tests.rs" ]]; then
    local total
    total="$(wc -l < "$path")"
    printf '%s %s\n' "0" "$total"
    return
  fi

  awk '
    function brace_delta(line, opens, closes) {
      opens = gsub(/\{/, "{", line)
      closes = gsub(/\}/, "}", line)
      return opens - closes
    }
    BEGIN {
      source = 0
      tests = 0
      pending_test_block = 0
      in_test_block = 0
      test_depth = 0
    }
    {
      line = $0
      if (in_test_block) {
        tests += 1
        test_depth += brace_delta(line)
        if (test_depth <= 0) {
          in_test_block = 0
          test_depth = 0
        }
        next
      }

      if (pending_test_block) {
        tests += 1
        test_depth += brace_delta(line)
        if (line ~ /\{/) {
          pending_test_block = 0
          if (test_depth > 0) {
            in_test_block = 1
          } else {
            test_depth = 0
          }
        }
        next
      }

      if (line ~ /^[[:space:]]*#\[cfg\(test\)\]/) {
        tests += 1
        pending_test_block = 1
        next
      }

      source += 1
    }
    END {
      printf "%d %d\n", source, tests
    }
  ' "$path"
}

module_name_for_file() {
  local package_dir="$1"
  local file="$2"
  local src_dir="$package_dir/src"
  local relative

  if [[ "$file" == "$src_dir/lib.rs" ]]; then
    printf '%s\n' "lib"
    return
  fi

  if [[ "$file" == "$src_dir/main.rs" ]]; then
    printf '%s\n' "main"
    return
  fi

  if [[ "$file" == "$src_dir/bin/"* ]]; then
    printf '%s\n' "bin"
    return
  fi

  if [[ "$file" == "$package_dir/tests/"* ]]; then
    printf '%s\n' "tests"
    return
  fi

  if [[ "$file" == "$package_dir/examples/"* ]]; then
    printf '%s\n' "examples"
    return
  fi

  if [[ "$file" == "$package_dir/benches/"* ]]; then
    printf '%s\n' "benches"
    return
  fi

  relative="${file#$src_dir/}"
  if [[ "$relative" == */* ]]; then
    printf '%s\n' "${relative%%/*}"
    return
  fi

  printf '%s\n' "${relative%.rs}"
}

print_row() {
  printf '%-24s %12s %12s %12s %10s\n' "$1" "$2" "$3" "$4" "$5"
}

collect_rust_files() {
  local package_dir="$1"
  {
    if [[ -d "$package_dir/src" ]]; then
      find "$package_dir/src" -type f -name '*.rs' -print
    fi
    for top_dir in tests examples benches; do
      if [[ -d "$package_dir/$top_dir" ]]; then
        find "$package_dir/$top_dir" -type f -name '*.rs' -print
      fi
    done
  } | LC_ALL=C sort
}

emit_package_summary() {
  local package_name="$1"
  local package_dir="$2"
  local source_lines=0
  local test_lines=0
  local file_count=0
  local file_source
  local file_tests

  while IFS= read -r file; do
    read -r file_source file_tests < <(count_file_lines "$file")
    source_lines=$((source_lines + file_source))
    test_lines=$((test_lines + file_tests))
    file_count=$((file_count + 1))
  done < <(collect_rust_files "$package_dir")

  print_row "$package_name" "$source_lines" "$test_lines" "$((source_lines + test_lines))" "$file_count"
}

emit_module_summary() {
  local package_name="$1"
  local package_dir="$2"
  local tmp_file
  local file
  local module
  local file_source
  local file_tests

  tmp_file="$(mktemp)"
  trap 'rm -f "$tmp_file"' RETURN

  while IFS= read -r file; do
    module="$(module_name_for_file "$package_dir" "$file")"
    read -r file_source file_tests < <(count_file_lines "$file")
    printf '%s\t%s\t%s\t1\n' "$module" "$file_source" "$file_tests" >> "$tmp_file"
  done < <(collect_rust_files "$package_dir")

  printf 'Package: %s\n\n' "$package_name"
  print_row "Module" "SourceLines" "TestLines" "TotalLines" "RustFiles"
  awk -F '\t' '
    {
      source[$1] += $2
      tests[$1] += $3
      files[$1] += $4
    }
    END {
      n = asorti(source, keys)
      for (i = 1; i <= n; i++) {
        key = keys[i]
        printf "%-24s %12d %12d %12d %10d\n", key, source[key], tests[key], source[key] + tests[key], files[key]
      }
    }
  ' "$tmp_file"

  rm -f "$tmp_file"
  trap - RETURN
}

if [[ "$by_module" -eq 1 ]]; then
  package_idx="$(package_index_by_name "${selected_packages[0]}")" || {
    echo "Unknown package: ${selected_packages[0]}" >&2
    exit 1
  }
  emit_module_summary "${package_names[$package_idx]}" "${package_dirs[$package_idx]}"
  exit 0
fi

print_row "Package" "SourceLines" "TestLines" "TotalLines" "RustFiles"

for package_name in "${selected_packages[@]}"; do
  package_idx="$(package_index_by_name "$package_name")" || {
    echo "Unknown package: $package_name" >&2
    exit 1
  }
  emit_package_summary "${package_names[$package_idx]}" "${package_dirs[$package_idx]}"
done
