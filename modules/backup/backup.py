"""Config backup: export/import config store as a single XML/JSON file."""
from __future__ import annotations
import io
import json
import os
import secrets
import tarfile
import time
from pathlib import Path
from typing import Any

BACKUP_DIR = "/var/lib/nfw/backups"
CONFIG_BASE = "/var/lib/nfw/config"


def export_full() -> bytes:
    """Export the entire config store as a tar.gz."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # Add config store
        if os.path.isdir(CONFIG_BASE):
            tar.add(CONFIG_BASE, arcname="config")
        # Add /etc/nfw (secrets, users)
        if os.path.isdir("/etc/nfw"):
            tar.add("/etc/nfw", arcname="etc-nfw",
                    filter=lambda ti: None if ti.name.endswith(".backups") else ti)
    buf.seek(0)
    return buf.read()


def import_full(data: bytes, author: str) -> dict:
    """Restore a config backup."""
    # Save current as auto-backup
    ts = time.strftime("%Y%m%d-%H%M%S")
    auto_path = f"{BACKUP_DIR}/auto-pre-import-{ts}.tar.gz"
    os.makedirs(BACKUP_DIR, exist_ok=True)
    with open(auto_path, "wb") as f:
        f.write(export_full())

    # Extract and replace
    import tempfile
    tmpdir = tempfile.mkdtemp()
    try:
        buf = io.BytesIO(data)
        with tarfile.open(fileobj=buf, mode="r:gz") as tar:
            tar.extractall(tmpdir)
        # Restore config store
        src_config = os.path.join(tmpdir, "config")
        if os.path.isdir(src_config):
            dst = CONFIG_BASE
            if os.path.isdir(dst):
                os.rename(dst, dst + ".old-" + ts)
            os.rename(src_config, dst)
        # Restore /etc/nfw (skip secret.key to avoid session invalidation)
        src_etc = os.path.join(tmpdir, "etc-nfw")
        if os.path.isdir(src_etc):
            for fn in os.listdir(src_etc):
                if fn == "secret.key":
                    continue  # keep our session key
                shutil_copy = os.path.join(src_etc, fn)
                dst = os.path.join("/etc/nfw", fn)
                if os.path.isfile(shutil_copy):
                    os.replace(shutil_copy, dst)
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)

    return {"imported": True, "auto_backup": auto_path}


def list_backups() -> dict:
    os.makedirs(BACKUP_DIR, exist_ok=True)
    items = []
    for fn in sorted(os.listdir(BACKUP_DIR), reverse=True):
        path = os.path.join(BACKUP_DIR, fn)
        if os.path.isfile(path):
            st = os.stat(path)
            items.append({
                "name": fn,
                "size": st.st_size,
                "mtime": st.st_mtime,
            })
    return {"backups": items}
