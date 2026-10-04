from __future__ import annotations

import base64
import binascii
import getpass
import json
import logging
import os
import re
import secrets
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dotenv import load_dotenv

from utils.paths import resolve_data_path

load_dotenv()

# This module intentionally avoids configuring the application's root logger.
# The application should configure logging once, at its entry point.
logger = logging.getLogger("CacheSecurity")

CACHE_KEY_ENV = "CACHE_SECRET_KEY"
CACHE_KEY_FILE_ENV = "CACHE_KEY_FILE"
MAX_TENANT_ID_LENGTH = 128
MAX_CACHE_BYTES = 10 * 1024 * 1024  # 10 MiB hard safety boundary
CACHE_FORMAT_VERSION = 2
HKDF_INFO_PREFIX = b"BreachScanner/cache/v2/tenant/"

# Tenant IDs are identifiers, not free-form user input.
_TENANT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")


def _validate_tenant_id(tenant_id: str) -> str:
    if not isinstance(tenant_id, str):
        raise TypeError("tenant_id must be a string")

    tenant_id = tenant_id.strip()
    if not tenant_id or len(tenant_id) > MAX_TENANT_ID_LENGTH:
        raise ValueError("Invalid tenant_id length")
    if not _TENANT_ID_RE.fullmatch(tenant_id):
        raise ValueError("Invalid tenant_id format")
    return tenant_id


def _mask_path(path: Path) -> str:
    # Cache file paths are normally non-sensitive, but do not put arbitrary
    # filesystem details into logs unless DEBUG logging is explicitly desired.
    try:
        return path.name
    except Exception:
        return "<cache-file>"


def _set_posix_permissions(path: Path, mode: int) -> None:
    if os.name == "posix":
        os.chmod(path, mode)


def _secure_directory(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(directory, 0o700)


def _get_windows_user_sid() -> str:
    """Return the current Windows account SID without invoking a shell."""
    result = subprocess.run(
        ["whoami", "/user", "/fo", "csv", "/nh"],
        shell=False,
        capture_output=True,
        text=True,
        check=True,
        timeout=5,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    line = result.stdout.strip()
    # CSV output is normally: "DOMAIN\\user","S-1-..."
    match = re.search(r'"(S-1-[0-9-]+)"', line)
    if not match:
        raise RuntimeError("Could not determine current Windows SID")
    return match.group(1)


def set_secure_file_permissions(file_path: Path) -> None:
    """Restrict a cache/key file to the current application account."""
    path = Path(file_path)

    try:
        if os.name == "posix":
            os.chmod(path, 0o600)
            return

        if os.name == "nt":
            sid = _get_windows_user_sid()
            # Disable inheritance and grant full control only to the current SID.
            # The SID is obtained programmatically; no shell interpolation occurs.
            # Reset inherited/default ACLs first, then disable inheritance and
            # grant the current account full control. No shell interpolation is used.
            subprocess.run(
                ["icacls", str(path), "/reset"],
                shell=False,
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            subprocess.run(
                [
                    "icacls",
                    str(path),
                    "/inheritance:r",
                    "/grant:r",
                    f"*{sid}:(F)",
                ],
                shell=False,
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return

        logger.warning("Unsupported platform for explicit cache ACL hardening")
    except Exception:
        # Fail closed for POSIX because chmod failure leaves the file potentially
        # readable by other local accounts. On Windows, ACL tooling may be absent;
        # report the issue rather than pretending the file is protected.
        logger.exception("Unable to harden cache file permissions: %s", _mask_path(path))
        raise


def _read_existing_key_file(path: Path) -> bytes:
    try:
        stat_result = path.lstat()
    except FileNotFoundError:
        raise

    if path.is_symlink():
        raise RuntimeError(f"Refusing symlink cache key file: {path.name}")
    if not path.is_file():
        raise RuntimeError(f"Cache key path is not a regular file: {path.name}")

    data = path.read_bytes()
    if not data:
        raise RuntimeError("Cache key file is empty; key recovery is not possible")

    try:
        Fernet(data)
    except (ValueError, TypeError):
        raise RuntimeError("Cache key file does not contain a valid Fernet key")

    if os.name == "posix" and (stat_result.st_mode & 0o077):
        # Best-effort correction, but do not allow a permission failure silently.
        os.chmod(path, 0o600)

    return data


def _create_key_file(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path.parent, 0o700)

    key = Fernet.generate_key()

    # O_EXCL prevents two processes from silently selecting different keys for
    # the same path. A complete key is written + fsynced before success.
    try:
        fd = os.open(
            str(path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError:
        return _read_existing_key_file(path)

    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(key)
            handle.flush()
            os.fsync(handle.fileno())
        set_secure_file_permissions(path)
        return key
    except Exception:
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass
        raise


def _get_base_key() -> bytes:
    env_key = os.getenv(CACHE_KEY_ENV, "").strip()
    if env_key:
        # CACHE_SECRET_KEY is deliberately required to be a real Fernet key.
        # Do not silently turn an arbitrary human password into a crypto key.
        try:
            key = env_key.encode("ascii")
            Fernet(key)
            return key
        except (UnicodeEncodeError, ValueError, TypeError, binascii.Error):
            raise RuntimeError(
                f"{CACHE_KEY_ENV} must be a valid Fernet key generated by Fernet.generate_key()"
            )

    # Anchored to the project root (not the cwd): starting the app from another directory must
    # not silently create a second key and orphan the existing cache.
    key_path = resolve_data_path(os.getenv(CACHE_KEY_FILE_ENV), ".cache_key")
    return _read_existing_key_file(key_path) if key_path.exists() else _create_key_file(key_path)


def derive_tenant_key(base_key: bytes, tenant_id: str = "default") -> bytes:
    """Derive a cryptographically separate Fernet key for every tenant."""
    tenant_id = _validate_tenant_id(tenant_id)

    # HKDF is appropriate here because base_key is already high-entropy key material.
    # tenant_id is domain-separated in HKDF info, so tenant keys are distinct.
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO_PREFIX + tenant_id.encode("utf-8"),
    ).derive(base_key)
    return base64.urlsafe_b64encode(derived)


def get_or_create_cache_key(tenant_id: str = "default") -> bytes:
    tenant_id = _validate_tenant_id(tenant_id)
    base_key = _get_base_key()
    return derive_tenant_key(base_key, tenant_id)


def _build_envelope(data: dict[str, Any], tenant_id: str) -> dict[str, Any]:
    return {
        "_cache_security": {
            "version": CACHE_FORMAT_VERSION,
            "tenant_id": tenant_id,
        },
        "data": data,
    }


def _unwrap_envelope(envelope: Any, tenant_id: str) -> dict[str, Any]:
    if not isinstance(envelope, dict):
        raise ValueError("Invalid cache envelope")

    meta = envelope.get("_cache_security")
    data = envelope.get("data")
    if not isinstance(meta, dict) or not isinstance(data, dict):
        raise ValueError("Invalid cache envelope structure")
    if meta.get("version") != CACHE_FORMAT_VERSION:
        raise ValueError("Unsupported cache format version")
    if meta.get("tenant_id") != tenant_id:
        raise ValueError("Cache tenant mismatch")
    return data


def _atomic_write(path: Path, payload: bytes) -> None:
    parent = path.parent
    _secure_directory(parent)

    fd, temp_name = tempfile.mkstemp(prefix=".cache-write-", dir=str(parent))
    temp_path = Path(temp_name)
    try:
        if os.name == "posix":
            os.chmod(temp_path, 0o600)

        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

        set_secure_file_permissions(temp_path)
        os.replace(temp_path, path)

        if os.name == "posix":
            # Persist the directory entry after atomic replacement.
            dir_fd = os.open(str(parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:
            pass


def save_encrypted_json(file_path: Path, data: dict[str, Any], tenant_id: str = "default") -> None:
    """Encrypt and atomically persist a tenant-bound JSON cache."""
    if not isinstance(data, dict):
        raise TypeError("data must be a dict")

    tenant_id = _validate_tenant_id(tenant_id)
    path = Path(file_path)
    _secure_directory(path.parent)

    envelope = _build_envelope(data, tenant_id)
    json_bytes = json.dumps(
        envelope,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(json_bytes) > MAX_CACHE_BYTES:
        raise ValueError("Cache payload exceeds maximum size")

    key = get_or_create_cache_key(tenant_id)
    encrypted_payload = Fernet(key).encrypt(json_bytes)
    if len(encrypted_payload) > MAX_CACHE_BYTES:
        raise ValueError("Encrypted cache payload exceeds maximum size")

    _atomic_write(path, encrypted_payload)


def load_encrypted_json(
    file_path: Path,
    tenant_id: str = "default",
    max_age_seconds: int | None = None,
) -> dict[str, Any] | None:
    """Load, authenticate, tenant-check, and optionally expire a cache token."""
    tenant_id = _validate_tenant_id(tenant_id)
    if max_age_seconds is not None and max_age_seconds < 0:
        raise ValueError("max_age_seconds must be >= 0 or None")
    path = Path(file_path)

    try:
        # Avoid exists()+read race and reject oversized cache blobs before allocation.
        if path.is_symlink():
            raise RuntimeError("Refusing symlink cache file")
        size = path.stat().st_size
        if size > MAX_CACHE_BYTES:
            raise ValueError("Cache file exceeds maximum size")

        encrypted_data = path.read_bytes()
        key = get_or_create_cache_key(tenant_id)
        fernet = Fernet(key)

        ttl = None
        if max_age_seconds is not None:
            if max_age_seconds < 0:
                raise ValueError("max_age_seconds must be >= 0 or None")
            ttl = int(max_age_seconds)

        plaintext = fernet.decrypt(encrypted_data, ttl=ttl)
        envelope = json.loads(plaintext.decode("utf-8"))
        return _unwrap_envelope(envelope, tenant_id)
    except FileNotFoundError:
        return None
    except (InvalidToken, ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        # Do not log exception text because it may disclose implementation details.
        logger.warning("Cache rejected: %s", type(exc).__name__)
        return None
    except Exception as exc:
        logger.warning("Cache unavailable: %s", type(exc).__name__)
        return None


# --------------------------------------------------------------------------------------
# Retention. Fernet enforces the TTL when a file is *read*, but expired files used to stay on
# disk forever. These helpers delete cache files only (never the key file).
# --------------------------------------------------------------------------------------

CACHE_FILE_PATTERNS = ("audit_cache_*.json", "breach_cache_*.json")


def _iter_cache_files(directory: Path):
    directory = Path(directory)
    if not directory.is_dir():
        return
    for pattern in CACHE_FILE_PATTERNS:
        for path in directory.rglob(pattern):
            try:
                if path.is_symlink() or not path.is_file():
                    continue
            except OSError:
                continue
            yield path


def purge_expired(directory: Path, max_age_seconds: float, now: float | None = None) -> int:
    """Delete cache files whose mtime is older than max_age_seconds. Returns the count."""
    import time

    max_age_seconds = float(max_age_seconds)
    if max_age_seconds < 0:
        raise ValueError("max_age_seconds must be >= 0")
    cutoff = (time.time() if now is None else now) - max_age_seconds
    removed = 0
    for path in _iter_cache_files(directory):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        except OSError:
            logger.warning("Could not remove expired cache file: %s", _mask_path(path))
    return removed


def clear_cache_files(*directories: Path) -> int:
    """Delete every cache file under the given directories. Returns the count."""
    removed = 0
    seen: set[Path] = set()
    for directory in directories:
        for path in _iter_cache_files(directory):
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            try:
                path.unlink()
                removed += 1
            except OSError:
                logger.warning("Could not remove cache file: %s", _mask_path(path))
    return removed
