#!/usr/bin/env python3
"""Refresh DNS blocklists. Driven by nfw-dnsblock-refresh.timer."""
import sys
sys.path.insert(0, "/opt/nfw")
sys.path.insert(0, "/opt/nfw/core")

import logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
LOG = logging.getLogger("nfw.dnsblock.helper")


def main() -> int:
    from config import store as cfg_store
    from modules.services import blocklists
    try:
        cfg = cfg_store.read()
    except Exception as e:
        LOG.error("cannot read config: %s", e)
        return 1
    state = blocklists.refresh(cfg)
    LOG.info("done — total=%s downloaded=%s manual=%s excluded=%s",
             state.get("total"), state.get("downloaded"),
             state.get("manual"), state.get("whitelisted_excluded"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
