#!/usr/bin/env bash
# Fail if generated files differ from tools/generate plus registry inventories.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

export PATH="${HOME}/.local/go/bin:/usr/local/go/bin:${PATH}"

go run ./tools/generate
go run ./tools/check-registries -write-docs -release

if ! git diff --exit-code -- docs/generated api/openapi.json web/src/generated; then
  echo "generated-file drift: generated artifacts do not match tools/generate and tools/check-registries -write-docs -release" >&2
  echo "run: make generate && git add docs/generated api/openapi.json web/src/generated" >&2
  exit 1
fi

untracked="$(git ls-files --others --exclude-standard -- docs/generated api/openapi.json web/src/generated || true)"
if [[ -n "$untracked" ]]; then
  echo "generated-file drift: untracked generated files:" >&2
  echo "$untracked" >&2
  echo "run: make generate && git add docs/generated" >&2
  exit 1
fi

echo "generated-file check: clean"
