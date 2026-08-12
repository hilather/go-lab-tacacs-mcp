#!/usr/bin/env bash
# Fail if private-key or cloud-token patterns appear in the tree.
# Extra paths may be passed as arguments (used by hook self-tests).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

patterns=(
  '-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----'
  'AKIA[0-9A-Z]{16}'
  'ghp_[A-Za-z0-9]{20,}'
  'github_pat_[A-Za-z0-9_]{20,}'
  'xox[baprs]-[A-Za-z0-9-]+'
  'TACLAB_SECRET_CANARY_[A-Za-z0-9_]+'
)

rg_excludes=(
  --glob '!.git/**'
  --glob '!web/node_modules/**'
  --glob '!web/dist/**'
  --glob '!bin/**'
  --glob '!dist/**'
)

fail=0

scan_tree() {
  local extra_path="${1:-}"
  if command -v rg >/dev/null 2>&1; then
    local args=( -n --hidden --no-messages "${rg_excludes[@]}" )
    if [[ -n "$extra_path" ]]; then
      args+=( "$extra_path" )
    else
      args+=( . )
    fi
    for pat in "${patterns[@]}"; do
      if rg "${args[@]}" -e "$pat"; then
        echo "secret-scan: matched pattern: $pat" >&2
        fail=1
      fi
    done
  else
    local targets=()
    if [[ -n "$extra_path" ]]; then
      targets+=( "$extra_path" )
    else
      targets+=( . )
    fi
    for pat in "${patterns[@]}"; do
      if grep -RInE --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=bin -e "$pat" "${targets[@]}"; then
        echo "secret-scan: matched pattern: $pat" >&2
        fail=1
      fi
    done
  fi
}

if [[ $# -gt 0 ]]; then
  for path in "$@"; do
    scan_tree "$path"
  done
else
  scan_tree
  if command -v gitleaks >/dev/null 2>&1; then
    if ! gitleaks detect --source . --no-banner --redact --config .gitleaks.toml; then
      echo "secret-scan: gitleaks failed" >&2
      fail=1
    fi
  fi
fi

if [[ "$fail" -ne 0 ]]; then
  echo "secret-scan: FAIL" >&2
  exit 1
fi
echo "secret-scan: clean"
