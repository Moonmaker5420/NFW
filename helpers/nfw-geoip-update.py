#!/usr/bin/env python3
"""Download DB-IP Lite Country CSV to /var/lib/nfw/geoip/."""
from __future__ import annotations
import gzip, logging, os, sys, urllib.request
from datetime import datetime, timezone
from pathlib import Path

LOG = logging.getLogger("geoip-update")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s",
                    handlers=[logging.FileHandler("/var/log/nfw/geoip-update.log"),
                              logging.StreamHandler()])

DEST = Path("/var/lib/nfw/geoip/dbip-country-lite.csv")


def candidate_urls() -> list[str]:
    now = datetime.now(timezone.utc)
    months = []
    for delta in (1, 0, 2):
        m = now.month - delta; y = now.year
        while m <= 0:
            m += 12; y -= 1
        months.append(f"{y}-{m:02d}")
    return [f"https://download.db-ip.com/free/dbip-country-lite-{m}.csv.gz"
            for m in months]


def main() -> int:
    DEST.parent.mkdir(parents=True, exist_ok=True)
    last_err = None
    for url in candidate_urls():
        LOG.info("trying %s", url)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NFW/1.0"})
            with urllib.request.urlopen(req, timeout=180) as r:
                data = r.read()
            text = gzip.decompress(data).decode("utf-8", errors="replace")
        except Exception as e:
            last_err = e
            LOG.warning("failed %s: %s", url, e)
            continue
        tmp = DEST.with_suffix(".csv.tmp")
        tmp.write_text(text)
        os.chmod(tmp, 0o644); os.chown(tmp, 0, 0)
        os.replace(tmp, DEST)
        LOG.info("wrote %s (%d bytes)", DEST, DEST.stat().st_size)
        return 0
    LOG.error("all URLs failed, last error: %s", last_err)
    return 1


if __name__ == "__main__":
    sys.exit(main())
