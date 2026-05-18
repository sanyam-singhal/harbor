#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$script_dir/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: read-source-lines.sh [options]

Options:
  --package <name>         Limit output to a Rust package. May be repeated.
  --module <name>          Limit output to a top-level module or src-relative file. May be repeated.
  --list-packages          List available Rust packages and exit.
  --list-modules           List top-level modules for the selected package and exit.
  --list-only              Alias for --list-packages.
  --write-markdown-file    Write one markdown file per selected package at the repo root.
  --include-readme         Include package README content before source.
  --help                   Show this help message.
EOF
}

selected_packages=()
selected_modules=()
list_packages=0
list_modules=0
write_markdown_file=0
include_readme=0

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
    --module)
      if [[ $# -lt 2 ]]; then
        echo "--module requires a value" >&2
        exit 1
      fi
      selected_modules+=("$2")
      shift 2
      ;;
    --list-packages|--list-only)
      list_packages=1
      shift
      ;;
    --list-modules)
      list_modules=1
      shift
      ;;
    --write-markdown-file|--write-markdown-files)
      write_markdown_file=1
      shift
      ;;
    --include-readme)
      include_readme=1
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

normalize_module_arg() {
  local value="$1"
  value="${value#src/}"
  value="${value#./}"
  value="${value%.rs}"
  printf '%s\n' "$value"
}

list_package_modules() {
  local package_dir="$1"
  local src_dir="$package_dir/src"

  if [[ ! -d "$src_dir" ]]; then
    return 0
  fi

  find "$src_dir" -mindepth 1 -maxdepth 1 \( -type d -o -type f -name '*.rs' \) -print \
    | LC_ALL=C sort \
    | while IFS= read -r path; do
        local name
        name="${path#$src_dir/}"
        name="${name%.rs}"
        if [[ "$name" != "lib" && "$name" != "main" ]]; then
          printf '%s\n' "$name"
        fi
      done
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

emit_non_test_lines() {
  local path="$1"
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
      next
    }
    {
      if (skipping_cfg_test_item) {
        brace_depth += brace_delta($0)
        if (brace_depth <= 0) {
          skipping_cfg_test_item = 0
          brace_depth = 0
        }
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
        next
      }

      print
    }
  ' "$path"
}

emit_readme_lines() {
  local package_dir="$1"
  local package_name="$2"
  local readme_path="$package_dir/README.md"
  local first_content
  local header_line
  local header

  if [[ ! -f "$readme_path" ]]; then
    return 0
  fi

  first_content="$(awk '
    {
      if ($0 ~ /[^[:space:]]/) {
        print NR ":" $0
        exit
      }
    }
  ' "$readme_path")"

  if [[ -n "$first_content" ]]; then
    header_line="${first_content#*:}"
    if [[ "$header_line" =~ ^#\ +(.+)$ ]]; then
      header="${BASH_REMATCH[1]}"
      header="${header//\`/}"
      if [[ "$header" == "$package_name" ]]; then
        tail -n +"$(( ${first_content%%:*} + 1 ))" "$readme_path"
        return 0
      fi
    fi
  fi

  cat "$readme_path"
}

file_matches_selected_module() {
  local src_dir="$1"
  local file="$2"
  local relative="${file#$src_dir/}"
  local relative_no_ext="${relative%.rs}"
  local module

  if [[ "${#selected_modules[@]}" -eq 0 ]]; then
    return 0
  fi

  for module in "${selected_modules[@]}"; do
    module="$(normalize_module_arg "$module")"
    if [[ "$relative_no_ext" == "$module" ]]; then
      return 0
    fi
    if [[ "$relative_no_ext" == "$module/"* ]]; then
      return 0
    fi
    if [[ "$relative_no_ext" == "$module/mod" ]]; then
      return 0
    fi
  done

  return 1
}

build_markdown() {
  local package_name="$1"
  local package_dir="$2"
  local src_dir="$package_dir/src"
  local has_content=0

  if [[ ! -d "$src_dir" ]]; then
    return 0
  fi

  printf '# %s\n\n' "$package_name"

  if [[ "$include_readme" -eq 1 ]]; then
    local readme_content
    readme_content="$(emit_readme_lines "$package_dir" "$package_name")"
    if [[ -n "$readme_content" ]]; then
      printf '## README\n\n'
      printf '%s\n' "$readme_content"
      printf '\n'
    fi
  fi

  printf '## Source\n\n'

  while IFS= read -r file; do
    if ! file_matches_selected_module "$src_dir" "$file"; then
      continue
    fi
    has_content=1
    relative="${file#$root/}"
    printf '### `%s`\n\n' "$relative"
    printf '```rust\n'
    emit_non_test_lines "$file"
    printf '```\n\n'
  done < <(find "$src_dir" -type f -name '*.rs' | LC_ALL=C sort)

  if [[ "$has_content" -eq 0 ]]; then
    printf '_No source files matched the selected modules._\n'
  fi
}

for selected_package in "${selected_packages[@]}"; do
  package_idx="$(package_index_by_name "$selected_package")" || {
    echo "Unknown package: $selected_package" >&2
    exit 1
  }

  package_name="${package_names[$package_idx]}"
  package_dir="${package_dirs[$package_idx]}"

  if [[ "$write_markdown_file" -eq 1 ]]; then
    target="$root/${package_name}.source.md"
    build_markdown "$package_name" "$package_dir" > "$target"
  else
    build_markdown "$package_name" "$package_dir"
  fi
done
