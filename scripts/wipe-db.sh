#!/usr/bin/env bash
# Orbital Exchange — full database wipe.
#
# Removes data/orbital.sqlite and its WAL/SHM sidecars. Next server boot
# re-creates the schema and re-seeds:
#   - 10 OWASP categories
#   - 30 planted-vulnerability slots (all 'undiscovered')
#   - 10 commissary products
#   - 2 default users (command/stationcommand admin, ryland/hailmary42 crew)
#
# This is the bigger hammer than POST /tracker/reset, which only flips
# tracker rows back to 'undiscovered' and preserves users/cart/comms.

set -euo pipefail

# Resolve repo root regardless of where the script is invoked from.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(dirname -- "$SCRIPT_DIR")"
DB_DIR="$REPO_ROOT/data"

if [[ ! -d "$DB_DIR" ]]; then
    echo "no data/ directory at $DB_DIR — nothing to wipe."
    exit 0
fi

removed=0
for f in "$DB_DIR"/orbital.sqlite "$DB_DIR"/orbital.sqlite-*; do
    if [[ -e "$f" ]]; then
        rm -f -- "$f"
        echo "removed $(basename -- "$f")"
        removed=1
    fi
done

if [[ $removed -eq 0 ]]; then
    echo "no orbital.sqlite found — already clean."
else
    echo "done. next 'go run ./cmd/server' will re-seed."
fi
