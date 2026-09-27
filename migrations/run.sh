#!/bin/bash
# Apply NFW config migrations between two versions.
# Usage: run.sh <from_version> <to_version> [--dry-run]
set -euo pipefail

FROM="${1:-}"
TO="${2:-}"
DRY_RUN=0
[ "${3:-}" = "--dry-run" ] && DRY_RUN=1

if [ -z "$FROM" ] || [ -z "$TO" ]; then
    echo "usage: $0 <from_version> <to_version> [--dry-run]" >&2
    exit 2
fi

# Same version — nothing to do
if [ "$FROM" = "$TO" ]; then
    exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Find migrations in ascending order by version
mapfile -t MIGRATIONS < <(ls "$SCRIPT_DIR"/*_to_*.sh 2>/dev/null | sort -V || true)

if [ ${#MIGRATIONS[@]} -eq 0 ]; then
    exit 0
fi

applied=0
for m in "${MIGRATIONS[@]}"; do
    [ -f "$m" ] || continue
    [ -x "$m" ] || chmod +x "$m" 2>/dev/null || true
    base="$(basename "$m" .sh)"
    # base = "<from>_to_<to>"
    m_from="${base%%_to_*}"
    m_to="${base##*_to_}"

    # Skip if we already have the target version
    if [ "$m_to" = "$FROM" ]; then
        continue
    fi
    # Skip if migration is older than installed
    if [ "$(printf '%s\n%s\n' "$m_from" "$FROM" | sort -V | head -1)" != "$FROM" ]; then
        # m_from < FROM → old migration, skip
        continue
    fi
    # Skip if migration goes past our target
    if [ "$(printf '%s\n%s\n' "$m_to" "$TO" | sort -V | tail -1)" != "$TO" ]; then
        # m_to > TO → future migration, skip
        continue
    fi

    echo "── migration: $base"
    if [ "$DRY_RUN" = "1" ]; then
        echo "   [dry-run] would execute $m"
    else
        if ! bash "$m" "$m_from" "$m_to"; then
            echo "   FAILED: $base" >&2
            exit 1
        fi
        echo "   ok"
    fi
    applied=$((applied+1))
done

if [ "$applied" = "0" ]; then
    exit 0
fi
