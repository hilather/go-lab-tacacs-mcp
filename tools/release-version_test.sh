#!/usr/bin/env bash
# Accept and reject cases for tools/release-version.sh.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
script="$root/tools/release-version.sh"
markerdir="$(mktemp -d)"
trap 'rm -rf "$markerdir"' EXIT
marker="$markerdir/marker"

accept() {
  local payload="$1" want="$2" out err
  err="$(mktemp)"
  out="$(bash "$script" "$payload" 2>"$err")"
  if [[ -s "$err" ]]; then
    echo "release-version-test: unexpected stderr for [$payload]: $(cat "$err")" >&2
    exit 1
  fi
  if [[ "$out" != "$want" ]]; then
    printf 'release-version-test: stdout mismatch for [%s]\ngot: [%s]\nwant: [%s]\n' "$payload" "$out" "$want" >&2
    exit 1
  fi
  rm -f "$err"
}

reject() {
  local payload="$1" out err status got
  err="$(mktemp)"
  status=0
  out="$(bash "$script" "$payload" 2>"$err")" || status=$?
  if [[ "$status" -ne 1 ]]; then
    echo "release-version-test: expected exit 1, got $status" >&2
    exit 1
  fi
  if [[ -n "$out" ]]; then
    echo "release-version-test: expected empty stdout, got [$out]" >&2
    exit 1
  fi
  got="$(cat "$err")"
  if [[ "$got" != "release-version: invalid version" ]]; then
    echo "release-version-test: stderr mismatch: [$got]" >&2
    exit 1
  fi
  if [[ -n "$payload" && "$got" == *"$payload"* ]]; then
    echo "release-version-test: stderr contains the input" >&2
    exit 1
  fi
  rm -f "$err"
}

accept v1.2.3 $'version=1.2.3\ntag=v1.2.3'
accept 1.2.3 $'version=1.2.3\ntag=v1.2.3'
accept v1.2.3-rc.1 $'version=1.2.3-rc.1\ntag=v1.2.3-rc.1'
accept 1.2.3-rc.1 $'version=1.2.3-rc.1\ntag=v1.2.3-rc.1'

reject ''
reject vpending
reject v1.2
reject v1.2.3.4
reject v01.2.3
reject 'v1.2.3+meta'
reject 'v1.2.3-'
reject 'v1.2.3-.'
reject 'v1.2.3 '
reject 'v1.2.3-rc;id'
reject 'vv1.2.3'

payload="v1\$(touch $marker)"
reject "$payload"
if [[ -e "$marker" ]]; then
  echo "release-version-test: injection command ran" >&2
  exit 1
fi
payload="v1.2.3-\$(touch $marker)"
reject "$payload"
if [[ -e "$marker" ]]; then
  echo "release-version-test: injection command ran" >&2
  exit 1
fi

echo "release-version-test: ok"
