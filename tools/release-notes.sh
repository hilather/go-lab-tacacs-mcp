#!/usr/bin/env bash
# Build dist/RELEASE_NOTES.md for a version tag.
# Requires CHANGELOG.md to contain "## [<version>]" (semver without leading v).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if [[ ! -f CHANGELOG.md ]]; then
  echo "release-notes: CHANGELOG.md not found in ${root}" >&2
  exit 2
fi

raw="${1:-${GITHUB_REF_NAME:-}}"
if [[ -z "$raw" ]]; then
  raw="$(git describe --tags --exact-match 2>/dev/null || true)"
fi
if [[ -z "$raw" ]]; then
  echo "release-notes: pass VERSION (vX.Y.Z or X.Y.Z) or run on an exact tag" >&2
  exit 2
fi

version="${raw#v}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-].*)?$ ]]; then
  echo "release-notes: invalid version $raw" >&2
  exit 2
fi

heading="## [${version}]"
if ! awk -v h="$heading" '
  $0 == h || index($0, h " ") == 1 {found=1; exit}
  END {exit !found}
' CHANGELOG.md; then
  echo "release-notes: CHANGELOG.md has no section ${heading}" >&2
  echo "release-notes: add the changes since the previous tag before tagging" >&2
  exit 1
fi

mkdir -p dist
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# Section body after "## [X.Y.Z]" or "## [X.Y.Z] — date", not "## [X.Y.Z-rc.1]".
awk -v h="$heading" '
  $0 == h || index($0, h " ") == 1 {grab=1; next}
  grab && /^## / {exit}
  grab {print}
' CHANGELOG.md > "$tmp"

if [[ ! -s "$tmp" ]]; then
  echo "release-notes: ${heading} exists but is empty" >&2
  exit 1
fi

prev=""
if git rev-parse --verify -q HEAD >/dev/null; then
  prev="$(git describe --tags --abbrev=0 --match 'v*' HEAD^ 2>/dev/null || true)"
fi

{
  echo "# TacLab ${version}"
  echo
  echo "Changes since ${prev:-the start of the repository}:"
  echo
  cat "$tmp"
  echo
  echo "## Commits"
  echo
  if [[ -n "$prev" ]]; then
    git log --pretty=format:'- %h %s' "${prev}..HEAD"
    echo
  else
    git log --pretty=format:'- %h %s' HEAD
    echo
  fi
} > dist/RELEASE_NOTES.md

echo "release-notes: wrote dist/RELEASE_NOTES.md (${version}, prev=${prev:-none})"
