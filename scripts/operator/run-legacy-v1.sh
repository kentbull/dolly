#!/usr/bin/env bash
# Install copied KERIpy/Dolly wheels and run the independent v1 operator script.
set -Eeuo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
: "${KERI_SOURCE:?Set KERI_SOURCE to the qualified KERIpy checkout}"
BASE_IMAGE=${KERI_IMAGE:-keripy-v1-operator:base}
IMAGE=${DOLLY_IMAGE:-dolly-v1-operator:dev}
VOLUME=${DOLLY_OPERATOR_VOLUME:-dolly-v1-operator}
KERI_DIRTY=false
DOLLY_DIRTY=false
[[ -z $(git -C "$KERI_SOURCE" status --porcelain) ]] || KERI_DIRTY=true
[[ -z $(git -C "$ROOT" status --porcelain) ]] || DOLLY_DIRTY=true
docker build -t "$BASE_IMAGE" -f "$KERI_SOURCE/scripts/v2-e2e/Dockerfile" "$KERI_SOURCE"
docker build -t "$IMAGE" -f "$ROOT/scripts/operator/Dockerfile" \
    --build-arg "KERI_IMAGE=$BASE_IMAGE" --build-arg "KERI_REVISION=$(git -C "$KERI_SOURCE" rev-parse HEAD)" \
    --build-arg "DOLLY_REVISION=$(git -C "$ROOT" rev-parse HEAD)" \
    --build-arg "KERI_DIRTY=$KERI_DIRTY" --build-arg "DOLLY_DIRTY=$DOLLY_DIRTY" "$ROOT"
docker run --rm -e "DEBUG_KLI=${DEBUG_KLI:-}" --mount "type=volume,src=$VOLUME,dst=/tmp" \
    --mount "type=volume,src=$VOLUME-state,dst=/usr/local/var" "$IMAGE"
