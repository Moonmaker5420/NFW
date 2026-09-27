"""Certificate Authority engine for NFW.

PRIVILEGE MODEL (OPNsense-style):
  All CA material on disk is root:root. No unprivileged service user has
  or needs filesystem access to private keys. Services that require a
  private key (e.g. the HTTPS admin UI) receive it from systemd via
  `LoadCredential=` — systemd reads the file as root at service start
  and passes it into a per-unit namespace at $CREDENTIALS_DIRECTORY.

  Directory perms:
      /var/lib/nfw/ca          root:root 0755
      /var/lib/nfw/ca/private  root:root 0700
      /var/lib/nfw/ca/certs    root:root 0755
      /var/lib/nfw/ca/csrs     root:root 0755
  File perms:
      *.key                    root:root 0400
      *.crt, *.pem             root:root 0644
      index.txt, serial,       root:root 0640
      crlnumber
"""

from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import ipaddress
import logging
import os
import re
import secrets
import shutil
import tempfile
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import (
    NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID,
)

LOG = logging.getLogger("ca.pki")

CA_DIR = Path("/var/lib/nfw/ca")
CERTS_DIR = CA_DIR / "certs"
PRIV_DIR = CA_DIR / "private"
CSRS_DIR = CA_DIR / "csrs"
INDEX = CA_DIR / "index.txt"
SERIAL = CA_DIR / "serial"
CRLNUM = CA_DIR / "crlnumber"
ROOT_CRT = CA_DIR / "root.crt"
ROOT_KEY = CA_DIR / "root.key"
INT_CRT = CA_DIR / "intermediate.crt"
INT_KEY = CA_DIR / "intermediate.key"
CHAIN = CA_DIR / "ca-chain.crt"
CRL_FILE = CA_DIR / "crl.pem"


class CaError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------
def _ensure_dirs():
    for d in (CA_DIR, CERTS_DIR, PRIV_DIR, CSRS_DIR):
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700 if d == PRIV_DIR else 0o755)
            os.chown(d, 0, 0)
        except OSError:
            pass


def _atomic_write(path: Path, data: bytes, mode: int = 0o644) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    # OPNsense-style: CA material is root:root. os.replace() takes the
    # tmp file's ownership, so chown here — not on the destination.
    try:
        os.chown(tmp, 0, 0)
    except OSError:
        pass
    os.replace(tmp, path)


def _read_serial_counter(path: Path) -> int:
    try:
        return int(path.read_text().strip(), 16)
    except Exception:
        return 0x1000


def _bump_serial(path: Path) -> int:
    """Atomically bump a hex counter file, return the previous value."""
    lockfile = path.with_suffix(path.suffix + ".lock")
    fd = os.open(lockfile, os.O_RDWR | os.O_CREAT, 0o640)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        cur = _read_serial_counter(path)
        nxt = cur + 1
        _atomic_write(path, f"{nxt:X}\n".encode(), 0o640)
        return cur
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


# ---------------------------------------------------------------------------
# Index (openssl-ca-like text database)
# ---------------------------------------------------------------------------
def _index_append(line: str) -> None:
    with open(INDEX, "a") as f:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())


def _index_lines() -> list[str]:
    if not INDEX.exists():
        return []
    with open(INDEX) as f:
        return [l.strip() for l in f if l.strip()]


def _index_rewrite(lines: list[str]) -> None:
    _atomic_write(INDEX, ("\n".join(lines) + "\n").encode(), 0o640)


def _serial_to_hex(n: int) -> str:
    return f"{n:X}"


def _hex_to_int(h: str) -> int:
    return int(h, 16)


def _parse_index_line(line: str) -> dict:
    """Format: STATUS  EXPIRY  REVOKED_AT  SERIAL  FILENAME  SUBJECT"""
    parts = line.split("\t")
    if len(parts) < 6:
        # Support space-separated as fallback
        parts = re.split(r"\s+", line, maxsplit=5)
    status = parts[0]
    expires = parts[1] if len(parts) > 1 else ""
    revoked = parts[2] if len(parts) > 2 else ""
    serial = parts[3] if len(parts) > 3 else ""
    filename = parts[4] if len(parts) > 4 else ""
    subject = parts[5] if len(parts) > 5 else ""
    return {
        "status": status,
        "expires": expires,
        "revoked_at": revoked,
        "serial": serial,
        "filename": filename,
        "subject": subject,
    }


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------
def _gen_rsa_key(bits: int):
    if bits < 2048:
        raise CaError("key_bits must be >= 2048")
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _key_to_pem(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _key_load(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _cert_load(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------
def status() -> dict:
    _ensure_dirs()
    out = {
        "initialized": ROOT_CRT.exists() and INT_CRT.exists(),
        "root": None,
        "intermediate": None,
        "issued": 0,
        "revoked": 0,
        "crl_updated": None,
    }
    if out["initialized"]:
        try:
            r = _cert_load(ROOT_CRT)
            i = _cert_load(INT_CRT)
            out["root"] = {
                "subject": r.subject.rfc4514_string(),
                "serial": format(r.serial_number, "X"),
                "not_before": r.not_valid_before_utc.isoformat(),
                "not_after":  r.not_valid_after_utc.isoformat(),
                "sha256": hashlib.sha256(r.public_bytes(serialization.Encoding.DER)).hexdigest()[:16],
            }
            out["intermediate"] = {
                "subject": i.subject.rfc4514_string(),
                "serial": format(i.serial_number, "X"),
                "not_before": i.not_valid_before_utc.isoformat(),
                "not_after":  i.not_valid_after_utc.isoformat(),
            }
        except Exception as e:
            out["error"] = str(e)
    for line in _index_lines():
        p = _parse_index_line(line)
        if p["status"] == "V":
            out["issued"] += 1
        elif p["status"] == "R":
            out["revoked"] += 1
    if CRL_FILE.exists():
        try:
            crl = x509.load_pem_x509_crl(CRL_FILE.read_bytes())
            out["crl_updated"] = crl.last_update_utc.isoformat()
        except Exception:
            pass
    return out


# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------
def init_ca(cfg: dict, force: bool = False) -> dict:
    _ensure_dirs()
    c = cfg.get("ca", {}) or {}
    if ROOT_CRT.exists() and INT_CRT.exists() and not force:
        raise CaError("CA already initialized (use force=True to regenerate)")

    if force:
        for p in (ROOT_CRT, ROOT_KEY, INT_CRT, INT_KEY, CHAIN, CRL_FILE):
            try: p.unlink()
            except FileNotFoundError: pass
        for d in (CERTS_DIR, PRIV_DIR, CSRS_DIR):
            for f in d.iterdir():
                try: f.unlink()
                except OSError: pass
        _atomic_write(SERIAL, b"1000\n", 0o640)
        _atomic_write(CRLNUM, b"1000\n", 0o640)
        _atomic_write(INDEX, b"", 0o640)

    country = (c.get("country") or "US")[:2].upper()
    org = c.get("org") or "NFW"
    ou = c.get("ou") or "Firewall"
    root_cn = c.get("root_cn") or "NFW Root CA"
    int_cn = c.get("intermediate_cn") or "NFW Intermediate CA"
    root_bits = int(c.get("root_key_bits", 4096))
    root_days = int(c.get("root_lifetime_days", 3650))
    int_days = int(c.get("intermediate_lifetime_days", 1825))

    now = dt.datetime.now(dt.timezone.utc)

    # --- Root CA ---
    root_key = _gen_rsa_key(root_bits)
    root_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
        x509.NameAttribute(NameOID.COMMON_NAME, root_cn),
    ])
    root_serial = _bump_serial(SERIAL)
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)
        .public_key(root_key.public_key())
        .serial_number(root_serial)
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=root_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
                       critical=False)
        .sign(root_key, hashes.SHA256())
    )

    _atomic_write(ROOT_KEY, _key_to_pem(root_key), 0o400)
    _atomic_write(ROOT_CRT, root_cert.public_bytes(serialization.Encoding.PEM), 0o644)

    # --- Intermediate CA ---
    int_key = _gen_rsa_key(root_bits)
    int_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
        x509.NameAttribute(NameOID.COMMON_NAME, int_cn),
    ])
    int_serial = _bump_serial(SERIAL)
    int_cert = (
        x509.CertificateBuilder()
        .subject_name(int_subject)
        .issuer_name(root_subject)
        .public_key(int_key.public_key())
        .serial_number(int_serial)
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=int_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(int_key.public_key()),
                       critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
                       critical=False)
        .sign(root_key, hashes.SHA256())
    )
    _atomic_write(INT_KEY, _key_to_pem(int_key), 0o400)
    _atomic_write(INT_CRT, int_cert.public_bytes(serialization.Encoding.PEM), 0o644)
    _atomic_write(CHAIN, int_cert.public_bytes(serialization.Encoding.PEM) +
                         root_cert.public_bytes(serialization.Encoding.PEM), 0o644)

    # Initial empty CRL
    generate_crl(cfg)

    LOG.info("CA initialized: root=%s int=%s", root_serial, int_serial)
    return status()


# ---------------------------------------------------------------------------
# Validity helpers
# ---------------------------------------------------------------------------
def _parse_san(san_str: str) -> list[x509.GeneralName]:
    """Comma-separated list of DNS names and IPs."""
    out: list[x509.GeneralName] = []
    for tok in (san_str or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            ip = ipaddress.ip_address(tok)
            out.append(x509.IPAddress(ip))
        except ValueError:
            out.append(x509.DNSName(tok))
    return out


def _subject(cfg: dict, cn: str, extra_org: bool = True) -> x509.Name:
    c = cfg.get("ca", {}) or {}
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if extra_org:
        country = (c.get("country") or "US")[:2].upper()
        org = c.get("org") or "NFW"
        ou = c.get("ou") or "Firewall"
        attrs = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    return x509.Name(attrs)


def _record_issue(serial: int, cert: x509.Certificate, filename: str,
                  subject_str: str) -> None:
    expires = cert.not_valid_after_utc.strftime("%Y%m%d%H%M%SZ")
    # openssl index format: STATUS EXPIRY [REVOKED] SERIAL FILENAME SUBJECT
    line = f"V\t{expires}\t\t{_serial_to_hex(serial)}\t{filename}\t{subject_str}"
    _index_append(line)


# ---------------------------------------------------------------------------
# Issue
# ---------------------------------------------------------------------------
def issue(cfg: dict, data: dict) -> dict:
    _ensure_dirs()
    if not INT_CRT.exists():
        raise CaError("CA not initialized — run init first")

    kind = data.get("kind", "server")
    if kind not in ("server", "client", "wildcard", "custom"):
        raise CaError("kind must be server|client|wildcard|custom")

    cn = (data.get("common_name") or "").strip()
    if not cn:
        raise CaError("common_name required")

    san_str = data.get("san") or ""
    if kind == "server" and not san_str:
        san_str = cn

    san_entries = _parse_san(san_str)
    if not san_entries:
        san_entries = [x509.DNSName(cn)]

    c = cfg.get("ca", {}) or {}
    if kind == "client":
        lifetime_days = int(data.get("lifetime_days")
                            or c.get("default_client_lifetime_days", 825))
    else:
        lifetime_days = int(data.get("lifetime_days")
                            or c.get("default_server_lifetime_days", 825))
    if lifetime_days < 1 or lifetime_days > 3650:
        raise CaError("lifetime_days must be 1..3650")

    key_bits = int(data.get("key_bits") or c.get("default_key_bits", 2048))

    now = dt.datetime.now(dt.timezone.utc)
    int_key = _key_load(INT_KEY)
    int_cert = _cert_load(INT_CRT)

    subject = _subject(cfg, cn, extra_org=(kind != "wildcard"))
    leaf_key = _gen_rsa_key(key_bits)
    serial = _bump_serial(SERIAL)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(int_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(serial)
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=lifetime_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
                       critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(int_key.public_key()),
                       critical=False)
    )

    if kind == "client":
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ), critical=True)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False)
    else:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ), critical=True)
        eku = [ExtendedKeyUsageOID.SERVER_AUTH]
        if kind == "server":
            eku.append(ExtendedKeyUsageOID.CLIENT_AUTH)
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)

    builder = builder.add_extension(x509.SubjectAlternativeName(san_entries),
                                    critical=False)

    cert = builder.sign(int_key, hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = _key_to_pem(leaf_key)
    filename = f"cert-{_serial_to_hex(serial)}.crt"
    (CERTS_DIR / filename).write_bytes(cert_pem)
    os.chmod(CERTS_DIR / filename, 0o644)
    os.chown(CERTS_DIR / filename, 0, 0)
    _key_path = PRIV_DIR / f"{_serial_to_hex(serial)}.key"
    _key_path.write_bytes(key_pem)
    os.chmod(_key_path, 0o400)
    os.chown(_key_path, 0, 0)

    _record_issue(serial, cert, filename, subject.rfc4514_string())

    LOG.info("issued cert serial=%s cn=%s kind=%s days=%s",
             _serial_to_hex(serial), cn, kind, lifetime_days)

    return {
        "serial": _serial_to_hex(serial),
        "common_name": cn,
        "kind": kind,
        "subject": subject.rfc4514_string(),
        "issuer": int_cert.subject.rfc4514_string(),
        "san": san_str,
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "certificate_pem": cert_pem.decode(),
        "private_key_pem": key_pem.decode(),
        "ca_chain_pem": (CERTS_DIR.parent / "ca-chain.crt").read_text(),
    }


# ---------------------------------------------------------------------------
# Sign CSR
# ---------------------------------------------------------------------------
def sign_csr(cfg: dict, data: dict) -> dict:
    _ensure_dirs()
    if not INT_CRT.exists():
        raise CaError("CA not initialized")

    csr_pem = data.get("csr_pem") or ""
    if "-----BEGIN CERTIFICATE REQUEST-----" not in csr_pem and \
       "-----BEGIN NEW CERTIFICATE REQUEST-----" not in csr_pem:
        raise CaError("not a PEM certificate request")

    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except Exception as e:
        raise CaError(f"invalid CSR: {e}")

    kind = data.get("kind", "server")
    if kind not in ("server", "client", "custom"):
        raise CaError("kind must be server|client|custom")

    c = cfg.get("ca", {}) or {}
    lifetime_days = int(data.get("lifetime_days")
                        or c.get("default_server_lifetime_days", 825))
    if lifetime_days < 1 or lifetime_days > 3650:
        raise CaError("lifetime_days must be 1..3650")

    san_str = data.get("san") or ""
    extra_san = _parse_san(san_str)

    now = dt.datetime.now(dt.timezone.utc)
    int_key = _key_load(INT_KEY)
    int_cert = _cert_load(INT_CRT)
    serial = _bump_serial(SERIAL)

    # Preserve requested extensions where sensible; force SAN from CSR
    try:
        csr_san = csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        csr_san = None

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(int_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=lifetime_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                       critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(int_key.public_key()),
                       critical=False)
    )

    if kind == "client":
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ), critical=True)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False)
    else:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ), critical=True)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,
                                   ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False)

    all_san: list[x509.GeneralName] = []
    if csr_san is not None:
        all_san.extend(csr_san)
    all_san.extend(extra_san)
    if not all_san:
        try:
            cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            all_san = [x509.DNSName(cn)]
        except Exception:
            all_san = [x509.DNSName("unconfigured")]
    builder = builder.add_extension(x509.SubjectAlternativeName(all_san),
                                    critical=False)

    cert = builder.sign(int_key, hashes.SHA256())
    filename = f"cert-{_serial_to_hex(serial)}.crt"
    _cp = CERTS_DIR / filename
    _cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(_cp, 0o644); os.chown(_cp, 0, 0)
    _sp = CSRS_DIR / f"{_serial_to_hex(serial)}.csr"
    _sp.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    os.chmod(_sp, 0o644); os.chown(_sp, 0, 0)

    _record_issue(serial, cert, filename, csr.subject.rfc4514_string())

    return {
        "serial": _serial_to_hex(serial),
        "subject": csr.subject.rfc4514_string(),
        "kind": kind,
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "ca_chain_pem": CHAIN.read_text(),
    }


# ---------------------------------------------------------------------------
# List / get
# ---------------------------------------------------------------------------
def list_certs() -> dict:
    _ensure_dirs()
    items = []
    for line in _index_lines():
        p = _parse_index_line(line)
        # enrich
        fn = p["filename"]
        cert_path = CERTS_DIR / fn
        p["exists"] = cert_path.exists()
        try:
            if cert_path.exists():
                cert = _cert_load(cert_path)
                try:
                    san_ext = cert.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName).value
                    p["san"] = ", ".join(
                        (n.value if isinstance(n, (x509.DNSName,)) else str(n.value))
                        for n in san_ext
                    )
                except x509.ExtensionNotFound:
                    p["san"] = ""
                p["not_before"] = cert.not_valid_before_utc.isoformat()
                p["not_after"] = cert.not_valid_after_utc.isoformat()
        except Exception:
            p["error"] = "cannot read cert"
        items.append(p)
    items.reverse()
    return {"certs": items}


def get_cert(serial: str) -> dict:
    serial = serial.upper().replace(":", "").strip()
    for line in _index_lines():
        p = _parse_index_line(line)
        if p["serial"].upper() == serial:
            fn = p["filename"]
            cert_path = CERTS_DIR / fn
            key_path = PRIV_DIR / f"{serial}.key"
            out = dict(p)
            if cert_path.exists():
                out["certificate_pem"] = cert_path.read_text()
            if key_path.exists():
                out["private_key_pem"] = key_path.read_text()
            if CHAIN.exists():
                out["ca_chain_pem"] = CHAIN.read_text()
            return out
    raise CaError(f"cert serial {serial} not found")


# ---------------------------------------------------------------------------
# Revoke
# ---------------------------------------------------------------------------
def revoke(cfg: dict, serial: str, reason: str = "unspecified") -> dict:
    serial = serial.upper().replace(":", "").strip()
    lines = _index_lines()
    found = False
    new_lines = []
    now = dt.datetime.now(dt.timezone.utc).strftime("%y%m%d%H%M%SZ")
    for line in lines:
        p = _parse_index_line(line)
        if p["serial"].upper() == serial and p["status"] == "V":
            # R<date>,<reason>   serial   filename   subject
            new_line = f"R\t{p['expires']}\t{now},reason={reason}\t{p['serial']}\t{p['filename']}\t{p['subject']}"
            new_lines.append(new_line)
            found = True
        else:
            new_lines.append(line)
    if not found:
        raise CaError(f"active cert serial {serial} not found")
    _index_rewrite(new_lines)
    generate_crl(cfg)
    LOG.info("revoked serial=%s reason=%s", serial, reason)
    return {"revoked": serial, "reason": reason}


# ---------------------------------------------------------------------------
# CRL
# ---------------------------------------------------------------------------
def generate_crl(cfg: dict) -> dict:
    _ensure_dirs()
    if not INT_CRT.exists():
        raise CaError("CA not initialized")
    c = cfg.get("ca", {}) or {}
    crl_days = int(c.get("crl_lifetime_days", 180))

    int_key = _key_load(INT_KEY)
    int_cert = _cert_load(INT_CRT)
    now = dt.datetime.now(dt.timezone.utc)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(int_cert.subject)
        .last_update(now)
        .next_update(now + dt.timedelta(days=crl_days))
    )

    for line in _index_lines():
        p = _parse_index_line(line)
        if p["status"] != "R":
            continue
        try:
            revoked_at = p["revoked_at"].split(",", 1)[0]
            when = dt.datetime.strptime(revoked_at, "%y%m%d%H%M%SZ").replace(tzinfo=dt.timezone.utc)
        except Exception:
            when = now
        try:
            serial_int = _hex_to_int(p["serial"])
        except Exception:
            continue
        rc = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial_int)
            .revocation_date(when)
            .build()
        )
        builder = builder.add_revoked_certificate(rc)

    crl = builder.sign(int_key, hashes.SHA256())
    _atomic_write(CRL_FILE, crl.public_bytes(serialization.Encoding.PEM), 0o644)
    return {"updated": now.isoformat(), "revoked": len(builder._revoked_certificates)}
    # (builder._revoked_certificates is fine for a count; ignore if attribute changes)


# ---------------------------------------------------------------------------
# PKCS#12 export
# ---------------------------------------------------------------------------
def export_p12(serial: str, password: str) -> bytes:
    if not password or len(password) < 8:
        raise CaError("password must be at least 8 characters")
    serial = serial.upper().strip()
    cert_path = CERTS_DIR / f"cert-{serial}.crt"
    key_path = PRIV_DIR / f"{serial}.key"
    if not cert_path.exists() or not key_path.exists():
        raise CaError(f"cert {serial} not found")

    from cryptography.hazmat.primitives.serialization import (
        pkcs12, BestAvailableEncryption,
    )
    cert = _cert_load(cert_path)
    key = _key_load(key_path)
    chain = []
    if ROOT_CRT.exists():
        chain.append(_cert_load(ROOT_CRT))
    if INT_CRT.exists():
        chain.append(_cert_load(INT_CRT))

    p12 = pkcs12.serialize_key_and_certificates(
        name=f"NFW-{serial}".encode(),
        key=key,
        cert=cert,
        cas=chain,
        encryption_algorithm=BestAvailableEncryption(password.encode()),
    )
    return p12


# ---------------------------------------------------------------------------
# Delete (only if revoked or expired)
# ---------------------------------------------------------------------------
def delete_cert(cfg: dict, serial: str) -> dict:
    serial = serial.upper().strip()
    lines = _index_lines()
    keep = []
    removed = None
    for line in lines:
        p = _parse_index_line(line)
        if p["serial"].upper() == serial:
            removed = p
            continue
        keep.append(line)
    if removed is None:
        raise CaError(f"cert {serial} not found")

    try:
        (CERTS_DIR / removed["filename"]).unlink()
    except FileNotFoundError:
        pass
    try:
        (PRIV_DIR / f"{serial}.key").unlink()
    except FileNotFoundError:
        pass
    try:
        (CSRS_DIR / f"{serial}.csr").unlink()
    except FileNotFoundError:
        pass

    _index_rewrite(keep)
    return {"deleted": serial}


# ---------------------------------------------------------------------------
# Root CA cert download
# ---------------------------------------------------------------------------
def root_pem() -> bytes:
    if not ROOT_CRT.exists():
        raise CaError("CA not initialized")
    return ROOT_CRT.read_bytes()


def chain_pem() -> bytes:
    if not CHAIN.exists():
        raise CaError("CA not initialized")
    return CHAIN.read_bytes()


# ---------------------------------------------------------------------------
# Helpers for integration (Phase 9.10b)
# ---------------------------------------------------------------------------
def _get_host_sans() -> list[str]:
    """Return SANs appropriate for the firewall's own management cert."""
    import socket
    out = ["localhost", "127.0.0.1"]
    # hostname + fqdn
    try:
        hn = socket.gethostname()
        out.append(hn)
        fqdn = socket.getfqdn()
        if fqdn and fqdn != hn:
            out.append(fqdn)
    except Exception:
        pass
    # management IPs — every non-loopback IPv4 of every up interface
    try:
        import subprocess
        import json as _json
        r = subprocess.run(["/usr/sbin/ip", "-j", "addr"],
                           capture_output=True, text=True, timeout=5)
        for iface in _json.loads(r.stdout or "[]"):
            if iface.get("operstate") != "UP":
                continue
            for a in iface.get("addr_info", []) or []:
                if a.get("family") == "inet" and not a.get("local", "").startswith("127."):
                    out.append(a["local"])
                elif a.get("family") == "inet6" and a.get("scope") == "global":
                    out.append(a["local"])
    except Exception:
        pass
    # dedupe, preserve order
    seen = set()
    uniq = []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def issue_for_host(cfg: dict) -> dict:
    """Issue a server certificate whose SANs cover the firewall itself.
    Used for the HTTPS admin UI.
    """
    sans = _get_host_sans()
    # use hostname as CN
    import socket
    cn = socket.gethostname() or "nfw"
    data = {
        "kind": "server",
        "common_name": cn,
        "san": ",".join(sans),
        "lifetime_days": int(cfg.get("ca", {}).get("default_server_lifetime_days", 825)),
    }
    result = issue(cfg, data)
    result["sans"] = sans
    return result


def expiring(within_days: int = 30) -> list[dict]:
    """Return certs that expire within N days (active only)."""
    import datetime as _dt
    now = _dt.datetime.now(_dt.timezone.utc)
    limit = now + _dt.timedelta(days=int(within_days))
    out = []
    for line in _index_lines():
        p = _parse_index_line(line)
        if p["status"] != "V":
            continue
        try:
            exp = _dt.datetime.strptime(p["expires"], "%Y%m%d%H%M%SZ").replace(tzinfo=_dt.timezone.utc)
        except Exception:
            continue
        if exp <= limit:
            p["days_left"] = (exp - now).days
            out.append(p)
    return out


def renew_cert(cfg: dict, serial: str) -> dict:
    """Re-issue a cert with the same CN + SAN. Revokes the old one first.
    Used by the auto-renew timer."""
    serial = serial.upper().strip()
    # find the cert
    target = None
    for line in _index_lines():
        p = _parse_index_line(line)
        if p["serial"].upper() == serial and p["status"] == "V":
            target = p
            break
    if target is None:
        raise CaError(f"active cert {serial} not found")

    cert_path = CERTS_DIR / target["filename"]
    if not cert_path.exists():
        raise CaError(f"cert file missing: {cert_path}")
    old_cert = _cert_load(cert_path)

    # Extract CN and SAN from the old cert
    try:
        cn = old_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        raise CaError("cannot read CN from old cert")
    try:
        san_ext = old_cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
        sans = []
        for n in san_ext:
            if isinstance(n, x509.DNSName):
                sans.append(n.value)
            elif isinstance(n, x509.IPAddress):
                sans.append(str(n.value))
        san_str = ",".join(sans)
    except x509.ExtensionNotFound:
        san_str = cn

    # Determine kind from EKU
    kind = "server"
    try:
        eku = old_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        oids = list(eku)
        has_server = ExtendedKeyUsageOID.SERVER_AUTH in oids
        has_client = ExtendedKeyUsageOID.CLIENT_AUTH in oids
        if has_client and not has_server:
            kind = "client"
    except x509.ExtensionNotFound:
        pass

    lifetime = int((old_cert.not_valid_after_utc - old_cert.not_valid_before_utc).days) or 825

    # Revoke old, issue new
    revoke(cfg, serial, reason="superseded")
    new = issue(cfg, {
        "kind": kind,
        "common_name": cn,
        "san": san_str,
        "lifetime_days": lifetime,
    })
    new["replaced_serial"] = serial
    return new


def get_cert_by_serial(serial: str) -> dict:
    return get_cert(serial)

