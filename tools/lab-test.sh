#!/usr/bin/env bash
# Build the 1.0 image, generate an ephemeral lab, run LAB-* including
# restart-reset and a subscriber that outlives listeners.http.write_timeout.
set -euo pipefail

export PATH="${HOME}/.local/go/bin:/usr/local/go/bin:${PATH}"

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if ! command -v docker >/dev/null 2>&1; then
  echo "lab-test: docker is required" >&2
  exit 2
fi

VERSION="${TACLAB_VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="${TACLAB_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
BUILDTIME="${TACLAB_BUILDTIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
UI_VERSION="${TACLAB_UI_VERSION:-0.0.0}"
IMAGE="${TACLAB_IMAGE:-ghcr.io/hilather/go-lab-tacacs-mcp:${VERSION}}"
LABTEST_IMAGE="${TACLAB_LABTEST_IMAGE:-ghcr.io/hilather/go-lab-tacacs-mcp:labtest}"
PROJECT="${TACLAB_PROJECT:-taclab-labtest-$$}"
KEEP="${TACLAB_KEEP:-0}"
WRITE_TIMEOUT="${TACLAB_WRITE_TIMEOUT:-2s}"

WORKDIR="${TACLAB_WORKDIR:-}"
cleanup() {
  local ec=$?
  docker compose -p "$PROJECT" \
    -f "$root/deployments/compose/compose.yaml" \
    -f "$root/deployments/compose/compose.lab-test.yaml" \
    --project-directory "${WORKDIR:-$root}" \
    down -v --remove-orphans >/dev/null 2>&1 || true
  docker compose -p "$PROJECT" \
    -f "$root/deployments/compose/compose.yaml" \
    -f "$root/deployments/compose/compose.tls-only.yaml" \
    -f "$root/deployments/compose/compose.lab-test.yaml" \
    --project-directory "${WORKDIR:-$root}" \
    down -v --remove-orphans >/dev/null 2>&1 || true
  docker compose -p "$PROJECT" \
    -f "$root/deployments/compose/compose.yaml" \
    -f "$root/deployments/compose/compose.combined.yaml" \
    -f "$root/deployments/compose/compose.lab-test.yaml" \
    --project-directory "${WORKDIR:-$root}" \
    down -v --remove-orphans >/dev/null 2>&1 || true
  docker compose -p "$PROJECT" \
    -f "$root/deployments/compose/compose.yaml" \
    -f "$root/deployments/compose/compose.radius-only.yaml" \
    -f "$root/deployments/compose/compose.lab-test.yaml" \
    --project-directory "${WORKDIR:-$root}" \
    down -v --remove-orphans >/dev/null 2>&1 || true
  if [[ "$KEEP" != "1" && -n "${WORKDIR:-}" && -d "$WORKDIR" ]]; then
    # Evidence is copied out before this when we fail.
    rm -rf "$WORKDIR"
  fi
  exit "$ec"
}
trap cleanup EXIT

if [[ "${TACLAB_SKIP_BUILD:-0}" != "1" ]]; then
  if docker buildx version >/dev/null 2>&1; then
    echo "lab-test: docker build --check"
    docker buildx build --check --target runtime "$root"
  else
    echo "lab-test: docker buildx not available; skipping --check"
  fi

  echo "lab-test: build $IMAGE"
  docker build \
    --target runtime \
    --build-arg "VERSION=$VERSION" \
    --build-arg "COMMIT=$COMMIT" \
    --build-arg "BUILDTIME=$BUILDTIME" \
    --build-arg "UI_VERSION=$UI_VERSION" \
    -t "$IMAGE" \
    "$root"

  echo "lab-test: build $LABTEST_IMAGE"
  docker build --target labtest -t "$LABTEST_IMAGE" "$root"
else
  echo "lab-test: TACLAB_SKIP_BUILD=1; using $IMAGE and $LABTEST_IMAGE"
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/taclab-lab.XXXXXX")"
echo "lab-test: generate lab in $WORKDIR"
go run ./tools/labgen \
  -force \
  -instance-id "labtest" \
  -http-write-timeout "$WRITE_TIMEOUT" \
  "$WORKDIR"

mkdir -p "$WORKDIR/evidence"
# mktemp is 0700; the labtest container is UID 65532.
chmod 0755 "$WORKDIR"
chmod -R a+rX "$WORKDIR"
chmod 0777 "$WORKDIR/evidence"
export TACLAB_IMAGE="$IMAGE"
export TACLAB_LABTEST_IMAGE="$LABTEST_IMAGE"
export TACLAB_CONTEXT="$root"
export TACLAB_VERSION="$VERSION"
export TACLAB_COMMIT="$COMMIT"
export TACLAB_BUILDTIME="$BUILDTIME"
export TACLAB_UI_VERSION="$UI_VERSION"
export TACLAB_WRITE_TIMEOUT="$WRITE_TIMEOUT"
export TACLAB_CONTAINER="${PROJECT}-taclab"

echo "lab-test: compose config"
docker compose -p "$PROJECT" \
  -f "$root/deployments/compose/compose.yaml" \
  -f "$root/deployments/compose/compose.lab-test.yaml" \
  --project-directory "$WORKDIR" \
  config >/dev/null

echo "lab-test: tls-only compose config (no host 49)"
tls_cfg="$(docker compose -p "${PROJECT}-tls-cfg" \
  -f "$root/deployments/compose/compose.yaml" \
  -f "$root/deployments/compose/compose.tls-only.yaml" \
  --project-directory "$WORKDIR" \
  config)"
if printf '%s\n' "$tls_cfg" | grep -E 'published:[[:space:]]*"?49"?[[:space:]]*$'; then
  echo "lab-test: tls-only overlay still publishes host port 49" >&2
  exit 1
fi

echo "lab-test: combined compose config (UDP 1812/1813)"
combined_cfg="$(docker compose -p "${PROJECT}-combined-cfg" \
  -f "$root/deployments/compose/compose.yaml" \
  -f "$root/deployments/compose/compose.combined.yaml" \
  --project-directory "$WORKDIR" \
  config)"
if ! printf '%s\n' "$combined_cfg" | grep -Eq 'target:[[:space:]]*"?1812"?'; then
  echo "lab-test: combined compose missing RADIUS access 1812" >&2
  exit 1
fi
if ! printf '%s\n' "$combined_cfg" | grep -Eq 'target:[[:space:]]*"?1813"?'; then
  echo "lab-test: combined compose missing RADIUS accounting 1813" >&2
  exit 1
fi
if ! printf '%s\n' "$combined_cfg" | grep -Eq 'target:[[:space:]]*"?3799"?'; then
  echo "lab-test: combined compose missing dynauth 3799" >&2
  exit 1
fi
if ! printf '%s\n' "$combined_cfg" | grep -Eq 'target:[[:space:]]*"?2083"?'; then
  echo "lab-test: combined compose missing radsec 2083" >&2
  exit 1
fi

echo "lab-test: radius-only compose config (no host 49)"
radius_cfg="$(docker compose -p "${PROJECT}-radius-cfg" \
  -f "$root/deployments/compose/compose.yaml" \
  -f "$root/deployments/compose/compose.radius-only.yaml" \
  --project-directory "$WORKDIR" \
  config)"
if printf '%s\n' "$radius_cfg" | grep -E 'published:[[:space:]]*"?49"?[[:space:]]*$'; then
  echo "lab-test: radius-only overlay still publishes host port 49" >&2
  exit 1
fi
if ! printf '%s\n' "$radius_cfg" | grep -Eq 'target:[[:space:]]*"?1812"?'; then
  echo "lab-test: radius-only compose missing RADIUS access 1812" >&2
  exit 1
fi

compose=(
  docker compose -p "$PROJECT"
  -f "$root/deployments/compose/compose.yaml"
  -f "$root/deployments/compose/compose.lab-test.yaml"
  --project-directory "$WORKDIR"
)

echo "lab-test: up taclab ($PROJECT)"
"${compose[@]}" up -d taclab

echo "lab-test: wait healthy"
for i in $(seq 1 60); do
  status="$("${compose[@]}" ps --format '{{.Health}}' taclab 2>/dev/null || true)"
  if [[ "$status" == "healthy" ]]; then
    break
  fi
  if [[ "$i" -eq 60 ]]; then
    "${compose[@]}" logs taclab | tee "$WORKDIR/evidence/taclab.log" || true
    echo "lab-test: taclab not healthy" >&2
    exit 1
  fi
  sleep 1
done

echo "lab-test: LAB-* suite"
"${compose[@]}" run --rm --no-deps integration-tests \
  -http=http://taclab:8080 \
  -legacy=taclab:4949 \
  -tls=taclab:4300 \
  -token-file=/run/secrets/api_admin_token \
  -secret-file=/run/secrets/lab_switches_tacacs_secret \
  -pki=/pki \
  -passwords=/lab/secrets/PASSWORDS.txt \
  -write-timeout="$WRITE_TIMEOUT" \
  -report=/lab/evidence/lab-test-report.json \
  | tee "$WORKDIR/evidence/labtest.log"

echo "lab-test: inspect non-root / read-only / caps"
cid="$("${compose[@]}" ps -q taclab || true)"
if [[ -z "$cid" ]]; then
  echo "lab-test: taclab container missing" >&2
  exit 1
fi
docker inspect --format \
  'ReadonlyRootfs={{.HostConfig.ReadonlyRootfs}} User={{.Config.User}} CapDrop={{json .HostConfig.CapDrop}} SecurityOpt={{json .HostConfig.SecurityOpt}}' \
  "$cid" | tee "$WORKDIR/evidence/inspect.txt"
inspect="$(cat "$WORKDIR/evidence/inspect.txt")"
echo "$inspect" | grep -q 'ReadonlyRootfs=true' || { echo "lab-test: rootfs is not read-only" >&2; exit 1; }
echo "$inspect" | grep -q 'User=10001:10001' || { echo "lab-test: user is not 10001:10001" >&2; exit 1; }
capdrop="$(docker inspect --format '{{json .HostConfig.CapDrop}}' "$cid")"
echo "$capdrop" | grep -q '"ALL"' || { echo "lab-test: CapDrop missing ALL: $capdrop" >&2; exit 1; }
secopt="$(docker inspect --format '{{json .HostConfig.SecurityOpt}}' "$cid")"
echo "$secopt" | grep -q 'no-new-privileges' || { echo "lab-test: SecurityOpt missing no-new-privileges: $secopt" >&2; exit 1; }

echo "lab-test: mutate overlay then restart"
"${compose[@]}" run --rm --no-deps integration-tests \
  -http=http://taclab:8080 \
  -legacy=taclab:4949 \
  -tls=taclab:4300 \
  -token-file=/run/secrets/api_admin_token \
  -secret-file=/run/secrets/lab_switches_tacacs_secret \
  -pki=/pki \
  -passwords=/lab/secrets/PASSWORDS.txt \
  -write-timeout="$WRITE_TIMEOUT" \
  -report=/lab/evidence/lab-test-mutate.json \
  -phase=mutate

"${compose[@]}" restart taclab

echo "lab-test: wait ready after restart"
for i in $(seq 1 30); do
  status="$("${compose[@]}" ps --format '{{.Health}}' taclab 2>/dev/null || true)"
  if [[ "$status" == "healthy" ]]; then
    break
  fi
  if [[ "$i" -eq 30 ]]; then
    echo "lab-test: not ready after restart" >&2
    exit 1
  fi
  sleep 1
done

"${compose[@]}" run --rm --no-deps integration-tests \
  -http=http://taclab:8080 \
  -legacy=taclab:4949 \
  -tls=taclab:4300 \
  -token-file=/run/secrets/api_admin_token \
  -secret-file=/run/secrets/lab_switches_tacacs_secret \
  -pki=/pki \
  -passwords=/lab/secrets/PASSWORDS.txt \
  -write-timeout="$WRITE_TIMEOUT" \
  -report=/lab/evidence/lab-test-restart.json \
  -phase=after-restart

echo "lab-test: TLS-only profile"
"${compose[@]}" down --remove-orphans >/dev/null 2>&1 || true
tlscompose=(
  docker compose -p "$PROJECT"
  -f "$root/deployments/compose/compose.yaml"
  -f "$root/deployments/compose/compose.tls-only.yaml"
  -f "$root/deployments/compose/compose.lab-test.yaml"
  --project-directory "$WORKDIR"
)
"${tlscompose[@]}" up -d taclab
for i in $(seq 1 30); do
  status="$("${tlscompose[@]}" ps --format '{{.Health}}' taclab 2>/dev/null || true)"
  if [[ "$status" == "healthy" ]]; then
    break
  fi
  if [[ "$i" -eq 30 ]]; then
    "${tlscompose[@]}" logs taclab | tee -a "$WORKDIR/evidence/taclab.log" || true
    echo "lab-test: tls-only taclab not healthy" >&2
    exit 1
  fi
  sleep 1
done
"${tlscompose[@]}" run --rm --no-deps integration-tests \
  -http=http://taclab:8080 \
  -legacy=taclab:4949 \
  -tls=taclab:4300 \
  -token-file=/run/secrets/api_admin_token \
  -secret-file=/run/secrets/lab_switches_tacacs_secret \
  -pki=/pki \
  -passwords=/lab/secrets/PASSWORDS.txt \
  -write-timeout="$WRITE_TIMEOUT" \
  -report=/lab/evidence/lab-test-tls-only.json \
  -phase=tls-only

"${tlscompose[@]}" logs --no-color taclab >"$WORKDIR/evidence/taclab.log" || true

echo "lab-test: combined TACACS+RADIUS profile"
"${tlscompose[@]}" down --remove-orphans >/dev/null 2>&1 || true
combinedcompose=(
  docker compose -p "$PROJECT"
  -f "$root/deployments/compose/compose.yaml"
  -f "$root/deployments/compose/compose.combined.yaml"
  -f "$root/deployments/compose/compose.lab-test.yaml"
  --project-directory "$WORKDIR"
)
"${combinedcompose[@]}" up -d taclab
for i in $(seq 1 30); do
  status="$("${combinedcompose[@]}" ps --format '{{.Health}}' taclab 2>/dev/null || true)"
  if [[ "$status" == "healthy" ]]; then
    break
  fi
  if [[ "$i" -eq 30 ]]; then
    "${combinedcompose[@]}" logs taclab | tee -a "$WORKDIR/evidence/taclab.log" || true
    echo "lab-test: combined taclab not healthy" >&2
    exit 1
  fi
  sleep 1
done
"${combinedcompose[@]}" run --rm --no-deps integration-tests \
  -http=http://taclab:8080 \
  -legacy=taclab:4949 \
  -tls=taclab:4300 \
  -radius-access=taclab:1812 \
  -radius-acct=taclab:1813 \
  -token-file=/run/secrets/api_admin_token \
  -secret-file=/run/secrets/lab_switches_tacacs_secret \
  -radius-secret-file=/run/secrets/lab_switches_radius_secret \
  -pki=/pki \
  -passwords=/lab/secrets/PASSWORDS.txt \
  -write-timeout="$WRITE_TIMEOUT" \
  -report=/lab/evidence/lab-test-combined.json \
  -phase=combined

echo "lab-test: RADIUS-only profile"
"${combinedcompose[@]}" down --remove-orphans >/dev/null 2>&1 || true
radiuscompose=(
  docker compose -p "$PROJECT"
  -f "$root/deployments/compose/compose.yaml"
  -f "$root/deployments/compose/compose.radius-only.yaml"
  -f "$root/deployments/compose/compose.lab-test.yaml"
  --project-directory "$WORKDIR"
)
"${radiuscompose[@]}" up -d taclab
for i in $(seq 1 30); do
  status="$("${radiuscompose[@]}" ps --format '{{.Health}}' taclab 2>/dev/null || true)"
  if [[ "$status" == "healthy" ]]; then
    break
  fi
  if [[ "$i" -eq 30 ]]; then
    "${radiuscompose[@]}" logs taclab | tee -a "$WORKDIR/evidence/taclab.log" || true
    echo "lab-test: radius-only taclab not healthy" >&2
    exit 1
  fi
  sleep 1
done
"${radiuscompose[@]}" run --rm --no-deps integration-tests \
  -http=http://taclab:8080 \
  -legacy=taclab:4949 \
  -tls=taclab:4300 \
  -radius-access=taclab:1812 \
  -radius-acct=taclab:1813 \
  -token-file=/run/secrets/api_admin_token \
  -secret-file=/run/secrets/lab_switches_tacacs_secret \
  -radius-secret-file=/run/secrets/lab_switches_radius_secret \
  -pki=/pki \
  -passwords=/lab/secrets/PASSWORDS.txt \
  -write-timeout="$WRITE_TIMEOUT" \
  -report=/lab/evidence/lab-test-radius-only.json \
  -phase=radius-only

"${radiuscompose[@]}" logs --no-color taclab >>"$WORKDIR/evidence/taclab.log" || true

echo "lab-test: secret canary scan of evidence"
canaries=()
if [[ -f "$WORKDIR/secrets/api_admin_token" ]]; then
  canaries+=("$(tr -d '\n' < "$WORKDIR/secrets/api_admin_token")")
fi
if [[ -f "$WORKDIR/secrets/lab_switches_tacacs_secret" ]]; then
  canaries+=("$(tr -d '\n' < "$WORKDIR/secrets/lab_switches_tacacs_secret")")
fi
if [[ -f "$WORKDIR/secrets/lab_switches_radius_secret" ]]; then
  canaries+=("$(tr -d '\n' < "$WORKDIR/secrets/lab_switches_radius_secret")")
fi
if [[ -f "$WORKDIR/secrets/PASSWORDS.txt" ]]; then
  while IFS= read -r line; do
    case "$line" in
      \#*|"") continue ;;
      *=*) canaries+=("${line#*=}") ;;
    esac
  done < "$WORKDIR/secrets/PASSWORDS.txt"
fi
fail=0
if [[ -d "$WORKDIR/evidence" ]]; then
  for c in "${canaries[@]}"; do
    [[ -z "$c" ]] && continue
    if grep -RFql -- "$c" "$WORKDIR/evidence"; then
      echo "lab-test: canary leaked into evidence" >&2
      fail=1
    fi
  done
fi
if grep -RFql -- '-----BEGIN' "$WORKDIR/evidence" 2>/dev/null; then
  echo "lab-test: PEM material in evidence" >&2
  fail=1
fi
if [[ "$fail" -ne 0 ]]; then
  exit 1
fi

mkdir -p "$root/dist"
cp -a "$WORKDIR/evidence/." "$root/dist/" 2>/dev/null || true
if [[ -f "$WORKDIR/evidence/lab-test-report.json" ]]; then
  cp "$WORKDIR/evidence/lab-test-report.json" "$root/dist/lab-test-report.json"
fi
echo "lab-test: PASS (report in dist/lab-test-report.json)"
