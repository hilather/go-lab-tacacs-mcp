#!/usr/bin/env bash
# Run on omarchy in go-lab-tacacs-mcp after: git fetch && git checkout chore/release-v1.5.2
set -euo pipefail
test -f .muse-changelog-rebuild/0.md
cat .muse-changelog-rebuild/0.md \
    .muse-changelog-rebuild/1.md \
    .muse-changelog-rebuild/2.md \
    .muse-changelog-rebuild/3.md \
    .muse-changelog-rebuild/4.md \
    .muse-changelog-rebuild/5.md \
    .muse-changelog-rebuild/6.md \
    .muse-changelog-rebuild/7.md > CHANGELOG.md
echo "12d031eee6b522b857d4893bc77de44433e091f05fc0148db533d688b7ea1832  CHANGELOG.md" | sha256sum -c -
rm -rf .muse-changelog-rebuild .changelog-parts .muse-size-probe.txt
./tools/release-notes.sh 1.5.2
git add CHANGELOG.md
git add -u
git status
git commit -m "$(cat <<'MSG'
docs: CHANGELOG for TacLab 1.5.2

Fill Unreleased with post-1.5.1 Dependabot #83–#90, promote to [1.5.2] — 2026-09-21.
Not a RADIUS completeness release; conformance stays partial.

— Muse
MSG
)"
echo "Push and open non-draft PR when ready. Do not merge/tag."
