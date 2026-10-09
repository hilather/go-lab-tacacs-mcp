#!/usr/bin/env bash
# The default Makefile VERSION is expanded inside recipe text. A git tag must
# not be able to run a command there. Explicit VERSION= overrides stay as given.
set -euo pipefail
export LC_ALL=C

root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

repo="$tmp/repo"
mkdir -p "$repo/tools" "$tmp/hooks"
cp "$root/Makefile" "$repo/Makefile"
cp "$root/tools/lab-test.sh" "$repo/tools/lab-test.sh"

git init -q "$repo"
git -C "$repo" config user.name test
git -C "$repo" config user.email test@example.invalid
git -C "$repo" config commit.gpgsign false
git -C "$repo" config tag.gpgsign false
git -C "$repo" config core.hooksPath "$tmp/hooks"
git -C "$repo" add Makefile tools/lab-test.sh
git -C "$repo" commit -q -m init

# check-ref-format accepts backticks and $(...) and rejects spaces.
# echo>file needs no space and creates a marker if the recipe shell evaluates it.
tag='v1`echo>MARKER`$(echo>MARKER2)'
git check-ref-format "refs/tags/$tag"
git -C "$repo" tag "$tag"

run_make() {
  env -u MAKEFLAGS -u MFLAGS make -C "$repo" --no-print-directory "$@"
}

assert_lab_version() {
  local label="$1" want="$2"
  shift 2
  local out
  out="$(env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE "$@" bash "$repo/tools/lab-test.sh")"
  if [[ "$out" != "$want" ]]; then
    printf 'make-version-test: %s\ngot: [%s]\nwant: [%s]\n' "$label" "$out" "$want" >&2
    exit 1
  fi
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

# Hostile tag is still the only tag on HEAD. Retag happens below.
assert_lab_version "hostile tag lab-test VERSION" "$want" -u TACLAB_VERSION TACLAB_PRINT_VERSION=1

# A tag with no allowed characters falls back to dev.
git -C "$repo" tag -d "$tag" >/dev/null
git -C "$repo" tag '$$$'
out="$(run_make print-version)"
if [[ "$out" != "dev" ]]; then
  printf 'make-version-test: empty filtered VERSION should be dev, got [%s]\n' "$out" >&2
  exit 1
fi

assert_lab_version "empty filtered lab-test VERSION" "dev" -u TACLAB_VERSION TACLAB_PRINT_VERSION=1
assert_lab_version "set-but-empty TACLAB_VERSION" "" TACLAB_VERSION= TACLAB_PRINT_VERSION=1
assert_lab_version "explicit TACLAB_VERSION" "v1.2.3/extra" TACLAB_VERSION='v1.2.3/extra' TACLAB_PRINT_VERSION=1

echo "make-version-test: ok"
