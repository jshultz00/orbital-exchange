#!/usr/bin/env bash
# Stop and remove the OWASP Juice Shop container started by juiceshop-start.sh.
# Per 00-scope.md §7, the container is disposable — no state is preserved.

set -euo pipefail

NAME="juice-shop"

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is not installed or not in PATH" >&2
    exit 1
fi

if ! docker ps -a --format '{{.Names}}' | grep -qx "${NAME}"; then
    echo "No ${NAME} container found; nothing to stop."
    exit 0
fi

echo "Removing ${NAME} container..."
docker rm -f "${NAME}" >/dev/null
echo "Stopped."
