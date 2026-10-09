#!/usr/bin/env bash
# Validate a release version and print version= and tag= lines.
# Accepts vX.Y.Z or X.Y.Z with an optional pre-release. No build metadata.
set -euo pipefail

raw="${1:-}"
version="$raw"
if [[ "$version" == v* ]]; then
  version="${version#v}"
fi

re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
if [[ ! "$version" =~ $re ]]; then
  printf '%s\n' 'release-version: invalid version' >&2
  exit 1
fi

printf 'version=%s\n' "$version"
printf 'tag=v%s\n' "$version"
