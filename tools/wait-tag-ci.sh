#!/usr/bin/env bash
# REV-CI-001: release publication requires this tag's push workflow, not main CI.
set -euo pipefail
repo="${1:?repository required}"
tag="${2:?tag required}"
sha="${3:?commit required}"
attempts="${TACLAB_CI_WAIT_ATTEMPTS:-60}"
wait_seconds="${TACLAB_CI_WAIT_SECONDS:-10}"
[[ "$attempts" =~ ^[1-9][0-9]*$ && "$wait_seconds" =~ ^[0-9]+$ ]]
run_id=""
for ((attempt = 0; attempt < attempts; attempt++)); do
  run_id="$(gh run list --repo "$repo" --workflow=ci.yml --branch "$tag" --event push --commit "$sha" \
    --json databaseId,headBranch,event,headSha | \
    jq -r --arg tag "$tag" --arg sha "$sha" '[.[] | select(.headBranch == $tag and .event == "push" and .headSha == $sha)][0].databaseId // empty')"
  if [[ -n "$run_id" ]]; then break; fi
  sleep "$wait_seconds"
done
if [[ -z "$run_id" ]]; then
  echo "release: no tag push ci.yml run found for ${tag} at ${sha}" >&2
  exit 1
fi
gh run watch "$run_id" --repo "$repo" --exit-status
