#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
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
