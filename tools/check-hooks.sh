#!/usr/bin/env bash
# Prove format, typecheck, drift, and secret hooks reject bad fixtures.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

export PATH="${HOME}/.local/go/bin:/usr/local/go/bin:${HOME}/.local/node-v22.14.0-linux-x64/bin:${PATH}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# gofmt must catch a deliberately malformed Go file.
cat > "$tmpdir/bad.go" <<'EOF'
package main
func main( ) { }
EOF
if [[ -z "$(gofmt -l "$tmpdir/bad.go")" ]]; then
  echo "hook-check: gofmt did not flag malformed spacing" >&2
  exit 1
fi
echo "hook-check: gofmt rejects malformed Go"

# tsc must catch a TypeScript type error.
cat > "$tmpdir/bad.ts" <<'EOF'
const n: number = "nope";
export const used = n;
EOF
if npx --prefix web --no-install tsc --strict --noEmit --pretty false --target ES2022 --module nodenext --moduleResolution nodenext "$tmpdir/bad.ts" 2>"$tmpdir/tsc.err"; then
  echo "hook-check: tsc did not reject a type error" >&2
  cat "$tmpdir/tsc.err" >&2
  exit 1
fi
echo "hook-check: tsc rejects type error"

# Generated-file drift must fail when the checked-in record is dirty.
mkdir -p "$tmpdir/repo/docs/generated" "$tmpdir/repo/tools"
cp go.mod "$tmpdir/repo/go.mod"
cp -a tools/generate "$tmpdir/repo/tools/generate"
cp docs/generated/toolchain.md "$tmpdir/repo/docs/generated/toolchain.md"
echo "stale" >> "$tmpdir/repo/docs/generated/toolchain.md"
(
  cd "$tmpdir/repo"
  git init -q
  git add docs/generated/toolchain.md
  git -c user.name=hook -c user.email=hook@example.invalid commit -q -m fixture
  if go run ./tools/generate >/dev/null && git diff --exit-code -- docs/generated >/dev/null; then
    echo "hook-check: drift detector missed a stale generated file" >&2
    exit 1
  fi
)
echo "hook-check: generated-file drift rejects stale output"

# Secret scan must catch a planted test secret.
# Build the PEM header at runtime so the hook source does not match the scanner.
printf -- '-----BEGIN %s PRIVATE KEY-----\nMIIBOgIBAAJBAK8=\n-----END %s PRIVATE KEY-----\n' RSA RSA > "$tmpdir/leaked.pem"
if tools/check-secrets.sh "$tmpdir/leaked.pem"; then
  echo "hook-check: secret scan missed a planted private key" >&2
  exit 1
fi
echo "hook-check: secret scan rejects planted test secret"

# Gitleaks allowlist must keep RADIUS RFC/lab vectors in testdata/protocol/radius/
# and must never exempt live Compose secret files.
: > "$tmpdir/clean.txt"
cat > "$tmpdir/gitleaks-missing-radius.toml" <<'EOF'
[allowlist]
paths = [ '''(^|/)internal/credentials/testdata/''' ]
EOF
if GITLEAKS_TOML="$tmpdir/gitleaks-missing-radius.toml" tools/check-secrets.sh "$tmpdir/clean.txt"; then
  echo "hook-check: secret scan accepted a gitleaks allowlist without testdata/protocol/radius/" >&2
  exit 1
fi
echo "hook-check: secret scan requires testdata/protocol/radius/ gitleaks allowlist"

cat > "$tmpdir/gitleaks-compose-secrets.toml" <<'EOF'
[allowlist]
paths = [
  '''(^|/)testdata/protocol/radius/''',
  '''(^|/)deployments/compose/secrets/''',
]
EOF
if GITLEAKS_TOML="$tmpdir/gitleaks-compose-secrets.toml" tools/check-secrets.sh "$tmpdir/clean.txt"; then
  echo "hook-check: secret scan accepted a live Compose secrets gitleaks allowlist" >&2
  exit 1
fi
echo "hook-check: secret scan rejects Compose secrets gitleaks allowlist"

# Pages workflow must reject configure-pages enablement: true.
# GITHUB_TOKEN cannot create a Pages site (Resource not accessible by integration).
cat > "$tmpdir/bad-pages.yml" <<'EOF'
permissions:
  pages: write
  id-token: write
jobs:
  deploy:
    steps:
      - uses: actions/configure-pages@v5
        with:
          enablement: true
      - uses: actions/deploy-pages@v4
        with:
          path: site
EOF
if tools/check-pages-workflow.sh "$tmpdir/bad-pages.yml"; then
  echo "hook-check: pages workflow check missed enablement: true" >&2
  exit 1
fi
echo "hook-check: pages workflow check rejects enablement: true"

cat > "$tmpdir/good-pages.yml" <<'EOF'
permissions:
  pages: write
  id-token: write
jobs:
  deploy:
    steps:
      - uses: actions/configure-pages@v5
      - uses: actions/upload-pages-artifact@v3
        with:
          path: site
      - uses: actions/deploy-pages@v4
EOF
if ! tools/check-pages-workflow.sh "$tmpdir/good-pages.yml"; then
  echo "hook-check: pages workflow check rejected a valid workflow" >&2
  exit 1
fi
echo "hook-check: pages workflow check accepts a valid workflow"

echo "hook-check: all dedicated validations passed"
