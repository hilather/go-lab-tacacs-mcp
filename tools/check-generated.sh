#!/usr/bin/env bash
# Fail if generated files differ from the stub generator output.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

export PATH="${HOME}/.local/go/bin:/usr/local/go/bin:${PATH}"

go run ./tools/generate

if ! git diff --exit-code -- docs/generated; then
  echo "generated-file drift: docs/generated does not match tools/generate" >&2
  echo "run: make generate && git add docs/generated" >&2
  exit 1
fi

untracked="$(git ls-files --others --exclude-standard -- docs/generated || true)"
if [[ -n "$untracked" ]]; then
  echo "generated-file drift: untracked generated files:" >&2
  echo "$untracked" >&2
  echo "run: make generate && git add docs/generated" >&2
  exit 1
fi

echo "generated-file check: clean"
