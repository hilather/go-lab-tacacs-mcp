#!/usr/bin/env bash
# Prove release-notes.sh requires a CHANGELOG section and writes notes.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
script="$root/tools/release-notes.sh"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

git_init() {
  git init -q "$1"
  git -C "$1" config user.name test
  git -C "$1" config user.email test@example.invalid
}

install_script() {
  mkdir -p "$1/tools"
  cp "$script" "$1/tools/release-notes.sh"
  chmod +x "$1/tools/release-notes.sh"
}

# Missing CHANGELOG section fails.
dir="$tmpdir/missing"
git_init "$dir"
install_script "$dir"
printf '# Changelog\n\n## [Unreleased]\n\n- n\n' > "$dir/CHANGELOG.md"
git -C "$dir" add CHANGELOG.md
git -C "$dir" commit -q -m init
if (cd "$dir" && ./tools/release-notes.sh 1.2.3) >/dev/null 2>"$tmpdir/err"; then
  echo "release-notes-test: expected failure without CHANGELOG section" >&2
  exit 1
fi
if ! grep -q 'CHANGELOG.md has no section' "$tmpdir/err"; then
  echo "release-notes-test: unexpected error:" >&2
  cat "$tmpdir/err" >&2
  exit 1
fi

# Matching dated section plus prior tag produces notes with commit range.
dir="$tmpdir/ok"
git_init "$dir"
install_script "$dir"
printf '# Changelog\n\n## [Unreleased]\n\n## [1.2.3] — 2026-08-13\n\n- added widget\n\n## [1.2.2] — 2026-08-01\n\n- older\n' > "$dir/CHANGELOG.md"
git -C "$dir" add CHANGELOG.md
git -C "$dir" commit -q -m 'v1.2.2 notes'
git -C "$dir" tag v1.2.2
printf 'x\n' > "$dir/code"
git -C "$dir" add code
git -C "$dir" commit -q -m 'add widget'
if ! (cd "$dir" && ./tools/release-notes.sh v1.2.3) >"$tmpdir/out"; then
  echo "release-notes-test: expected success" >&2
  cat "$tmpdir/out" >&2
  exit 1
fi
if ! grep -q 'added widget' "$dir/dist/RELEASE_NOTES.md"; then
  echo "release-notes-test: notes missing changelog body" >&2
  cat "$dir/dist/RELEASE_NOTES.md" >&2
  exit 1
fi
if ! grep -q 'add widget' "$dir/dist/RELEASE_NOTES.md"; then
  echo "release-notes-test: notes missing commit list" >&2
  cat "$dir/dist/RELEASE_NOTES.md" >&2
  exit 1
fi
if ! grep -q 'v1.2.2' "$dir/dist/RELEASE_NOTES.md"; then
  echo "release-notes-test: notes missing previous tag" >&2
  cat "$dir/dist/RELEASE_NOTES.md" >&2
  exit 1
fi

# 1.0.0 must not bind to a 1.0.0-rc.1 heading.
dir="$tmpdir/prefix"
git_init "$dir"
install_script "$dir"
printf '# Changelog\n\n## [Unreleased]\n\n## [1.0.0-rc.1] — 2026-08-01\n\n- rc only\n' > "$dir/CHANGELOG.md"
git -C "$dir" add CHANGELOG.md
git -C "$dir" commit -q -m rc
if (cd "$dir" && ./tools/release-notes.sh 1.0.0) >/dev/null 2>"$tmpdir/prefix.err"; then
  echo "release-notes-test: 1.0.0 must not match 1.0.0-rc.1" >&2
  exit 1
fi
if ! grep -q 'CHANGELOG.md has no section' "$tmpdir/prefix.err"; then
  echo "release-notes-test: unexpected prefix error:" >&2
  cat "$tmpdir/prefix.err" >&2
  exit 1
fi

echo "release-notes-test: ok"
