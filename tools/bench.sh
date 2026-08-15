#!/usr/bin/env bash
# Run hot-path benches, or fail clearly until any Benchmark exists.
# Argon2id KDF benches stay in internal/credentials and are not run here.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

export PATH="${HOME}/.local/go/bin:/usr/local/go/bin:${PATH}"

pkgs=(internal/tacacs internal/policy internal/state internal/aaa internal/radius)
found=0
for pkg in "${pkgs[@]}"; do
  if [[ -d "$pkg" ]] && grep -R --include='*_test.go' -E '^func Benchmark' "$pkg" >/dev/null 2>&1; then
    found=1
    break
  fi
done

if [[ "$found" -eq 0 ]]; then
  echo "bench: no Benchmark functions in internal/{tacacs,policy,state,aaa,radius}" >&2
  echo "bench: refusing to report success until real benches exist" >&2
  exit 1
fi

go test -bench=. -benchmem ./internal/tacacs/... ./internal/policy/... ./internal/state/... ./internal/aaa ./internal/radius/...
