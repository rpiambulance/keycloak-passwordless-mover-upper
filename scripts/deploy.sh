#!/usr/bin/env bash
# Build the amd64 image locally, push it to GHCR, and trigger a Coolify redeploy.
# Requires: docker buildx, a `docker login ghcr.io` session, and COOLIFY_URL /
# COOLIFY_API_TOKEN / COOLIFY_APP_UUID / REGISTRY_IMAGE in the environment (or in
# a .env.deploy file next to this script).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ -f "$SCRIPT_DIR/.env.deploy" ]]; then
  set -a; source "$SCRIPT_DIR/.env.deploy"; set +a
fi

: "${REGISTRY_IMAGE:?Set REGISTRY_IMAGE (e.g. ghcr.io/rpiambulance/keycloak-passwordless-mover-upper)}"
: "${COOLIFY_URL:?Set COOLIFY_URL}"
: "${COOLIFY_API_TOKEN:?Set COOLIFY_API_TOKEN}"
: "${COOLIFY_APP_UUID:?Set COOLIFY_APP_UUID}"

# Tag defaults to the current commit; fall back to a timestamp before the first
# commit exists so a fresh clone can still ship something traceable.
if [[ -n "${1:-}" ]]; then
  TAG="$1"
elif TAG="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null)"; then
  if ! git -C "$REPO_ROOT" diff --quiet HEAD 2>/dev/null; then
    echo "==> Warning: working tree is dirty; tagging $TAG anyway"
  fi
else
  TAG="$(date -u +%Y%m%d%H%M%S)"
  echo "==> No git commit found; using timestamp tag $TAG"
fi

echo "==> Building $REGISTRY_IMAGE:$TAG (linux/amd64)"
docker buildx build \
  --platform linux/amd64 \
  --tag "$REGISTRY_IMAGE:$TAG" \
  --tag "$REGISTRY_IMAGE:latest" \
  --push \
  "$REPO_ROOT"

echo "==> Triggering Coolify redeploy of $COOLIFY_APP_UUID"
# Coolify's /deploy is POST-only; uuid and force stay in the query string.
curl --fail-with-body -sS -X POST \
  -H "Authorization: Bearer $COOLIFY_API_TOKEN" \
  -H "Accept: application/json" \
  "$COOLIFY_URL/api/v1/deploy?uuid=$COOLIFY_APP_UUID&force=false"

echo
echo "==> Done. Deployed $REGISTRY_IMAGE:$TAG"
