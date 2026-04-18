#!/bin/bash
#
# Build, export and import Docker images for pi-custom-captive.
#
# Usage:
#   bash build-images.sh           # build all images (default)
#   bash build-images.sh build     # same as above
#   bash build-images.sh export    # export to pi-custom-captive-images.tar.gz
#   bash build-images.sh import    # import from pi-custom-captive-images.tar.gz
#   bash build-images.sh all       # build + export
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARCHIVE="${SCRIPT_DIR}/pi-custom-captive-images.tar.gz"
IMAGES="nginx:1.27-alpine pi-custom-captive-app:latest"

build_images() {
    echo "=== Pulling nginx:1.27-alpine ==="
    docker pull nginx:1.27-alpine

    echo ""
    echo "=== Building pi-custom-captive-app ==="
    docker build -t pi-custom-captive-app:latest \
        -f "${SCRIPT_DIR}/Dockerfile" \
        "${SCRIPT_DIR}/"

    echo ""
    echo "=== Images built ==="
    docker images --format "  {{.Repository}}:{{.Tag}}  {{.Size}}" | grep -E "^  (pi-custom-captive-|nginx:1.27-alpine)"
}

export_images() {
    echo "=== Exporting images to ${ARCHIVE} ==="
    docker save ${IMAGES} | gzip > "${ARCHIVE}"
    echo "  $(du -h "${ARCHIVE}" | cut -f1)  ${ARCHIVE}"
    echo "=== Export done ==="
}

import_images() {
    if [ ! -f "${ARCHIVE}" ]; then
        echo "ERROR: ${ARCHIVE} not found."
        echo "Run '$(basename "$0") export' first or copy the archive here."
        exit 1
    fi
    echo "=== Importing images from ${ARCHIVE} ==="
    gunzip -c "${ARCHIVE}" | docker load
    echo ""
    echo "=== Images loaded ==="
    docker images --format "  {{.Repository}}:{{.Tag}}  {{.Size}}" | grep -E "^  (pi-custom-captive-|nginx:1.27-alpine)"
    echo ""
    echo "Now run:  docker compose up -d"
}

CMD="${1:-build}"

case "${CMD}" in
    build)  build_images ;;
    export) export_images ;;
    import) import_images ;;
    all)    build_images; echo ""; export_images ;;
    *)
        echo "Usage: $(basename "$0") {build|export|import|all}"
        exit 1
        ;;
esac
