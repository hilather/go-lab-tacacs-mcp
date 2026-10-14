#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
release="$root/.github/workflows/release.yml"

# Floating majors (actions/checkout@v7) fail. A SHA pin with "# v7.0.1" does not.
if grep -nE 'uses:[[:space:]]*[^#[:space:]]+@v[0-9]' "$release"; then
  echo 'FAIL: release.yml has a floating action major tag' >&2
  exit 1
fi

# The ref itself must be the 40-hex SHA, not a later @<hex> in a comment.
pin_re='uses:[[:space:]]*[^#[:space:]@]+@[0-9a-f]{40}([[:space:]]+#|$)'
use_count=0
while IFS= read -r line; do
  use_count=$((use_count + 1))
  if [[ ! "$line" =~ $pin_re ]]; then
    echo "FAIL: uses line is not a full commit pin: $line" >&2
    exit 1
  fi
done < <(grep -nE '^[[:space:]]*(- )?uses:' "$release" || true)
if [[ "$use_count" -eq 0 ]]; then
  echo 'FAIL: release.yml has no uses: lines' >&2
  exit 1
fi

pkg_count="$(grep -c 'packages: write' "$release" || true)"
if [[ "$pkg_count" -ne 1 ]]; then
  echo "FAIL: packages: write must appear exactly once (got ${pkg_count})" >&2
  exit 1
fi

images_count="$(awk '/^  images:$/,/^  publish:$/' "$release" | grep -c 'packages: write' || true)"
if [[ "$images_count" -ne 1 ]]; then
  echo 'FAIL: packages: write must be on the images job' >&2
  exit 1
fi

# A job-level permissions block replaces the workflow set, so images must
# restate checkout (contents: read) and the OIDC token for provenance/SBOM.
images_perms="$(awk '/^  images:$/{f=1} f&&/^    permissions:$/{p=1;next} p&&/^      [a-z-]+:/{print;next} p{exit}' "$release")"
for want in 'contents: read' 'packages: write' 'id-token: write'; do
  if ! grep -qx "      ${want}" <<<"$images_perms"; then
    echo "FAIL: images job permissions must include ${want}" >&2
    exit 1
  fi
done
if grep -qE 'write-all|packages:[[:space:]]*["'"'"']write' "$release"; then
  echo 'FAIL: release.yml must not use write-all or a quoted packages grant' >&2
  exit 1
fi

if awk '/^jobs:/{exit} {print}' "$release" | grep -q 'packages: write'; then
  echo 'FAIL: workflow-level permissions must not grant packages: write' >&2
  exit 1
fi

cd "$root"
needle='(-[0-9A-Za-z-]+'
needle+='(\.[0-9A-Za-z-]+)*)?$'
hits="$(grep -rlF -- "$needle" tools .github | sort || true)"
if [[ "$hits" != "tools/release-version.sh" ]]; then
  echo 'FAIL: version pattern must live only in tools/release-version.sh' >&2
  printf '%s\n' "$hits" >&2
  exit 1
fi
if grep -F '([.-].*)?' tools/release-notes.sh >/dev/null; then
  echo 'FAIL: release-notes.sh must not keep a private version pattern' >&2
  exit 1
fi
bash "$root/tools/release-version_test.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"
cat > "$tmp/bin/gh" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1 $2" == "run list" ]]; then
  if [[ "$*" == *"--jq"* ]]; then
    # The old workflow selected the latest run for the commit, regardless of ref.
    printf '101\n'
  else
    cat "$CI_FIXTURE"
  fi
elif [[ "$1 $2" == "run watch" ]]; then
  printf '%s\n' "$3" >> "$CI_WATCHED"
  exit "${CI_WATCH_STATUS:-0}"
else
  exit 99
fi
MOCK
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH" CI_FIXTURE="$tmp/runs.json" CI_WATCHED="$tmp/watched"
export TACLAB_CI_WAIT_ATTEMPTS=2 TACLAB_CI_WAIT_SECONDS=0
export GITHUB_REPOSITORY=test/taclab GITHUB_REF_NAME=v1.2.3 GITHUB_SHA=abc123
write_workflow() {
  python3 - "$root/.github/workflows/release.yml" > "$tmp/workflow.sh" <<'PY'
import os, sys
text = open(sys.argv[1]).read().split('- name: Wait for tag ci-gate', 1)[1]
body = text.split('run: |\n', 1)[1].split('\n\n  images:', 1)[0]
body = '\n'.join(line[10:] for line in body.splitlines())
for key, var in [('github.sha', 'GITHUB_SHA'), ('github.repository', 'GITHUB_REPOSITORY'), ('github.ref_name', 'GITHUB_REF_NAME')]:
    body = body.replace('${{ ' + key + ' }}', os.environ[var])
print(body)
PY
}
write_workflow
printf '[{"databaseId":101,"headBranch":"main","event":"push","headSha":"abc123"}]\n' > "$CI_FIXTURE"
if (cd "$root" && bash "$tmp/workflow.sh") >/dev/null 2>&1; then
  echo 'FAIL: a green main run must not satisfy the tag gate' >&2
  exit 1
fi
[[ ! -e "$CI_WATCHED" ]]
printf '[{"databaseId":101,"headBranch":"main","event":"push","headSha":"abc123"},{"databaseId":202,"headBranch":"v1.2.3","event":"pull_request","headSha":"abc123"},{"databaseId":302,"headBranch":"v1.2.3","event":"push","headSha":"wrong"},{"databaseId":303,"headBranch":"v1.2.3","event":"push","headSha":"abc123"}]\n' > "$CI_FIXTURE"
(cd "$root" && bash "$tmp/workflow.sh") >/dev/null
[[ "$(cat "$CI_WATCHED")" == 303 ]]
export CI_WATCH_STATUS=1
if (cd "$root" && bash "$tmp/workflow.sh") >/dev/null 2>&1; then
  echo 'FAIL: failed tag CI must block release' >&2
  exit 1
fi
unset CI_WATCH_STATUS
rm "$CI_WATCHED"
export CI_PWNED="$tmp/pwned"
export GITHUB_REF_NAME='v$(touch${IFS}${CI_PWNED})'
python3 - "$CI_FIXTURE" <<'PY'
import json, os, sys
with open(sys.argv[1], "w") as output:
    json.dump([{"databaseId": 304, "headBranch": os.environ["GITHUB_REF_NAME"], "event": "push", "headSha": "abc123"}], output)
PY
write_workflow
(cd "$root" && bash "$tmp/workflow.sh") >/dev/null 2>&1 || true
if [[ -e "$CI_PWNED" ]]; then
  echo 'FAIL: tag input executed shell code' >&2
  exit 1
fi
[[ "$(cat "$CI_WATCHED")" == 304 ]]
printf 'tag CI gate regression cases passed\n'
