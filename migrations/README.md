# NFW migrations

Schema / config migrations that run during `install.sh --upgrade`.

## Convention

- One file per version transition: `<from>_to_<to>.sh`
- Called with two args: `$1=from_version  $2=to_version`
- Must be idempotent — safe to re-run
- Must exit 0 on success, non-zero on failure
- Migrations run in ascending version order, only the ones where
  `from >= installed && to <= target`

## Example

    # migrations/0.1.0_to_0.2.0.sh
    #!/bin/bash
    set -euo pipefail
    FROM="$1"; TO="$2"
    echo "[$FROM → $TO] renaming config.system.hostname"
    python3 - <<'PY'
    import json
    p = "/var/lib/nfw/config/active.json"
    cfg = json.load(open(p))
    if "system" in cfg and "host" in cfg["system"]:
        cfg["system"]["hostname"] = cfg["system"].pop("host")
        json.dump(cfg, open(p, "w"), indent=2)
    PY

## What runs them

`migrations/run.sh` — called from `install.sh` during upgrade, between
code replacement and venv rebuild. Silent no-op if no migrations apply.

## Testing a migration

    # Dry-run
    bash migrations/run.sh 0.1.0 0.2.0 --dry-run

    # Real
    bash migrations/run.sh 0.1.0 0.2.0
