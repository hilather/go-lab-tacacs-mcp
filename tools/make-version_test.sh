#!/usr/bin/env bash
# The default Makefile VERSION is expanded inside recipe text. A git tag must
# not be able to run a command there. Explicit VERSION= overrides stay as given.
set -euo pipefail
export LC_ALL=C

root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

repo="$tmp/repo"
mkdir -p "$repo" "$tmp/hooks"
cp "$root/Makefile" "$repo/Makefile"

git init -q "$repo"
git -C "$repo" config user.name test
git -C "$repo" config user.email test@example.invalid
git -C "$repo" config commit.gpgsign false
git -C "$repo" config tag.gpgsign false
git -C "$repo" config core.hooksPath "$tmp/hooks"
git -C "$repo" add Makefile
git -C "$repo" commit -q -m init

# check-ref-format accepts backticks and $(...) and rejects spaces.
# echo>file needs no space and creates a marker if the recipe shell evaluates it.
tag='v1`echo>MARKER`$(echo>MARKER2)'
git check-ref-format "refs/tags/$tag"
git -C "$repo" tag "$tag"

run_make() {
  env -u MAKEFLAGS -u MFLAGS make -C "$repo" --no-print-directory "$@"
}

status=0
out="$(run_make print-version 2>"$tmp/make.err")" || status=$?
if [[ -e "$repo/MARKER" || -e "$repo/MARKER2" ]]; then
  echo "make-version-test: hostile tag ran inside a recipe" >&2
  [[ -e "$repo/MARKER" ]] && echo "make-version-test: created MARKER" >&2
  [[ -e "$repo/MARKER2" ]] && echo "make-version-test: created MARKER2" >&2
  exit 1
fi
if [[ "$status" -ne 0 ]]; then
  echo "make-version-test: make print-version failed" >&2
  cat "$tmp/make.err" >&2
  exit 1
fi

want="v1echoMARKERechoMARKER2"
if [[ "$out" != "$want" ]]; then
  printf 'make-version-test: filtered VERSION mismatch\ngot: [%s]\nwant: [%s]\n' "$out" "$want" >&2
  exit 1
fi
if [[ ! "$out" =~ ^[A-Za-z0-9._+-]+$ ]]; then
  printf 'make-version-test: VERSION has unsafe characters: [%s]\n' "$out" >&2
  exit 1
fi

# Command-line VERSION= is the operator's value and is not filtered.
out="$(run_make VERSION='v1.2.3/extra' print-version)"
if [[ "$out" != 'v1.2.3/extra' ]]; then
  printf 'make-version-test: VERSION= override mismatch: [%s]\n' "$out" >&2
  exit 1
fi

# A tag with no allowed characters falls back to dev.
git -C "$repo" tag -d "$tag" >/dev/null
git -C "$repo" tag '$$$'
out="$(run_make print-version)"
if [[ "$out" != "dev" ]]; then
  printf 'make-version-test: empty filtered VERSION should be dev, got [%s]\n' "$out" >&2
  exit 1
fi

echo "make-version-test: ok"
