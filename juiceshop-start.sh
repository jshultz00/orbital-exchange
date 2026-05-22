#!/usr/bin/env bash
# Start a clean OWASP Juice Shop instance for the pentest engagement.
# Removes any existing container of the same name so each run is reproducible
# (see 00-scope.md §7: "container is treated as disposable and rebuilt").

set -euo pipefail

NAME="juice-shop"
IMAGE="bkimminich/juice-shop:latest"
PORT="3000"
URL="http://localhost:${PORT}"

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is not installed or not in PATH" >&2
    exit 1
fi

if docker ps -a --format '{{.Names}}' | grep -qx "${NAME}"; then
    echo "Removing existing ${NAME} container..."
    docker rm -f "${NAME}" >/dev/null
fi

echo "Pulling ${IMAGE}..."
docker pull "${IMAGE}"

echo "Starting ${NAME} on ${URL}..."
docker run -d \
    --name "${NAME}" \
    -p "${PORT}:3000" \
    "${IMAGE}" >/dev/null

echo -n "Waiting for Juice Shop to respond"
for _ in $(seq 1 60); do
    if curl -fsS -o /dev/null "${URL}"; then
        echo
        echo "Ready: ${URL}"
        exit 0
    fi
    echo -n "."
    sleep 1
done

echo
echo "error: Juice Shop did not become ready within 60s" >&2
echo "Container logs:" >&2
docker logs --tail 50 "${NAME}" >&2
exit 1
