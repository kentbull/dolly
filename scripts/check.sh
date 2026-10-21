#!/bin/sh
# Build copied source and install real wheels; neither source nor state is host-mounted.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${KERI_SOURCE:?Set KERI_SOURCE to the qualified KERIpy checkout}"
keri_image=${KERI_IMAGE:-keripy-v2-refactor:dolly-dependency}
image=${DOLLY_IMAGE:-dolly-v2-refactor:dev}
volume=${DOLLY_TEST_VOLUME:-dolly-v2-refactor-tests}
git -C "$KERI_SOURCE" rev-parse HEAD
git -C "$KERI_SOURCE" status --short
docker build -t "$keri_image" -f "$KERI_SOURCE/scripts/v2-e2e/Dockerfile" "$KERI_SOURCE"
docker build --build-arg "KERI_IMAGE=$keri_image" -t "$image" -f "$root/scripts/Dockerfile" "$root"
if [ "$#" -eq 0 ]; then
    set -- /dolly/tests
fi
docker run --rm \
    --mount "type=volume,src=$volume,dst=/tmp" \
    --mount "type=volume,src=$volume-state,dst=/usr/local/var" \
    -e PYTHONDONTWRITEBYTECODE=1 "$image" \
    python -m pytest -p no:cacheprovider -q "$@"
