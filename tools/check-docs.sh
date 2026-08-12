#!/usr/bin/env bash
# Lightweight docs checks that do not rewrite normative protocol language.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

fail=0

if grep -nE '\[[^]]+\]\((\.\./|docs/|AGENTS\.md|LICENSE|README\.md)' README.md | grep -vE 'https://'; then
  echo "docs-check: root README.md must use absolute GitHub HTTPS links for cross-file targets" >&2
  fail=1
fi

required=(
  https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/CANONICAL_DESIGN.md
  https://github.com/hilather/go-lab-tacacs-mcp/blob/main/AGENTS.md
  https://github.com/hilather/go-lab-tacacs-mcp/blob/main/docs/ARCHITECTURE.md
)
for url in "${required[@]}"; do
  if ! grep -Fq "$url" README.md; then
    echo "docs-check: README.md missing required link $url" >&2
    fail=1
  fi
done

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
echo "docs-check: clean"
