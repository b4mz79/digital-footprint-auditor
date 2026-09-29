import os
import json
import logging
import getpass
import subprocess
import base64
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("CacheSecurity")

def set_secure_file_permissions(file_path: Path) -> None:
    """Mengamankan hak akses file untuk POSIX dan Windows dengan aman."""
    if os.name == "posix":
        try:
            os.chmod(file_path, 0o600)
        except Exception as e:
            logger.warning(f"Gagal mengatur chmod pada {file_path}: {e}")
    elif os.name == "nt":
        try:
            username = getpass.getuser()
            # FIX: Menambahkan double quotes pada username untuk mencegah injeksi/error akibat spasi
            cmd = ["icacls", str(file_path), "/inheritance:r", "/grant:r", f'"{username}":(R,W)']
            subprocess.run(cmd, shell=False, capture_output=True, check=True)
        except Exception as e:
            logger.warning(f"Gagal mengatur icacls Windows pada {file_path}: {e}")

def derive_tenant_key(base_key: bytes, tenant_id: str = "default") -> bytes:
    """Mekanisme Tenant Isolation dengan KDF yang menggunakan env salt dinamis."""
    # FIX: Gunakan global salt dari env untuk menambah entropi, fallback ke static jika tidak ada
    global_salt = os.getenv("KDF_GLOBAL_SALT", "default_fallback_salt").encode("utf-8")
    salt = hashes.Hash(hashes.SHA256())
    salt.update(global_salt + f"tenant_salt_{tenant_id}".encode("utf-8"))
    digest_salt = salt.finalize()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=digest_salt,
        iterations=200000, # Ditingkatkan dari 100k ke 200k (Standard Modern)
    )
    return base64.urlsafe_b64encode(kdf.derive(base_key))

def get_or_create_cache_key(tenant_id: str = "default") -> bytes:
    env_key = os.getenv("CACHE_SECRET_KEY")
    if env_key:
        base_key = env_key.encode("utf-8")
    else:
        key_file = Path(".cache_key")
        if not key_file.exists():
            # FIX: Atomic file creation untuk mencegah TOCTOU Race Condition
            try:
                fd = os.open(str(key_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                base_key = Fernet.generate_key()
                with os.fdopen(fd, 'wb') as f:
                    f.write(base_key)
                set_secure_file_permissions(key_file)
            except FileExistsError:
                base_key = key_file.read_bytes()
        else:
            base_key = key_file.read_bytes()

    return derive_tenant_key(base_key, tenant_id) if tenant_id and tenant_id != "default" else base_key

def save_encrypted_json(file_path: Path, data: dict, tenant_id: str = "default") -> None:
    file_path.parent.mkdir(parents=True, exist_ok=True)
    key = get_or_create_cache_key(tenant_id)
    fernet = Fernet(key)
    
    json_bytes = json.dumps(data, ensure_ascii=False).encode("utf-8")
    encrypted_payload = fernet.encrypt(json_bytes)
    
    with open(file_path, "wb") as f:
        f.write(encrypted_payload)
    set_secure_file_permissions(file_path)

def load_encrypted_json(file_path: Path, tenant_id: str = "default") -> dict | None:
    if not file_path.exists():
        return None
    try:
        key = get_or_create_cache_key(tenant_id)
        fernet = Fernet(key)
        encrypted_data = file_path.read_bytes()
        return json.loads(fernet.decrypt(encrypted_data).decode("utf-8"))
    except Exception as e:
        logger.warning(f"Gagal mendekripsi cache: {e}")
        return None