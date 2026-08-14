#!/usr/bin/env bash
# Reject Pages workflow shapes that cannot succeed with GITHUB_TOKEN.
set -euo pipefail

file="${1:-.github/workflows/pages.yml}"

if [[ ! -f "$file" ]]; then
  echo "pages-workflow-check: missing $file" >&2
  exit 1
fi

fail=0

# Match a YAML key only. Comments and error strings may mention the
# forbidden input without setting it.
if grep -nE '^[[:space:]]+enablement:[[:space:]]*true[[:space:]]*(#.*)?$' "$file"; then
  echo "pages-workflow-check: $file must not set configure-pages enablement: true" >&2
  echo "pages-workflow-check: GITHUB_TOKEN cannot create a Pages site (HTTP 403 Resource not accessible by integration)." >&2
  echo "pages-workflow-check: A repo admin enables it once: gh api --method POST repos/<owner>/<repo>/pages -f build_type=workflow" >&2
  fail=1
fi

if ! grep -qE '^[[:space:]]*pages:[[:space:]]*write[[:space:]]*$' "$file"; then
  echo "pages-workflow-check: $file must request pages: write" >&2
  fail=1
fi

if ! grep -qE '^[[:space:]]*id-token:[[:space:]]*write[[:space:]]*$' "$file"; then
  echo "pages-workflow-check: $file must request id-token: write" >&2
  fail=1
fi

if ! grep -qE 'uses:[[:space:]]*actions/configure-pages@' "$file"; then
  echo "pages-workflow-check: $file must use actions/configure-pages" >&2
  fail=1
fi

if ! grep -qE 'uses:[[:space:]]*actions/deploy-pages@' "$file"; then
  echo "pages-workflow-check: $file must use actions/deploy-pages" >&2
  fail=1
fi

if ! grep -qE 'path:[[:space:]]*site[[:space:]]*$' "$file"; then
  echo "pages-workflow-check: $file must upload artifact path site" >&2
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
echo "pages-workflow-check: $file ok"
