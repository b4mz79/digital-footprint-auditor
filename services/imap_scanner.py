import os
import imaplib
import email
import re
import time
from pathlib import Path
from typing import Any
from email.header import decode_header, make_header
from email.utils import parseaddr

from dotenv import load_dotenv
from cache_security import load_encrypted_json, save_encrypted_json
from utils.cache_identity import hmac_identity, tenant_identity
from utils.envutil import env_bool
from utils.paths import resolve_data_path

from utils.domains import is_ignored_sender, root_domain
from utils.envutil import env_non_negative_int
from utils.logging_setup import get_logger
from utils.privacy import NUMERIC_CODE_PATTERN, mask_email
from utils.translations import t

load_dotenv()
logger = get_logger("IMAPScanner")

# Module-owned persistent cache.
IMAP_CACHE_ENABLED_ENV = "IMAP_CACHE_ENABLED"
IMAP_CACHE_SCHEMA_VERSION = 1
IMAP_CACHE_MAX_AGE_HOURS = 12.0
IMAP_CACHE_DIR = resolve_data_path(os.getenv("IMAP_CACHE_DIR"), "cache/imap")

def imap_cache_enabled() -> bool:
    return env_bool(IMAP_CACHE_ENABLED_ENV, True)

def _cache_path(email: str, tenant_id: str) -> Path:
    tenant_dir = IMAP_CACHE_DIR / tenant_identity(tenant_id)
    tenant_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        try: os.chmod(tenant_dir, 0o700)
        except OSError: pass
    return tenant_dir / f"imap_cache_{hmac_identity(email.strip().lower())}.json"

def load_imap_cache(email: str, *, tenant_id: str = "default", max_age_hours: float = IMAP_CACHE_MAX_AGE_HOURS) -> list[dict[str, Any]] | None:
    if max_age_hours < 0: raise ValueError("max_age_hours must be >= 0")
    try:
        data = load_encrypted_json(_cache_path(email, tenant_id), tenant_id=tenant_id, max_age_seconds=int(max_age_hours * 3600))
        if not isinstance(data, dict) or data.get("cache_schema_version") != IMAP_CACHE_SCHEMA_VERSION: return None
        findings = data.get("findings")
        return findings if isinstance(findings, list) and all(isinstance(x, dict) for x in findings) else None
    except Exception: return None

def save_imap_cache(email: str, findings: list[dict[str, Any]], *, tenant_id: str = "default") -> None:
    if not isinstance(findings, list): raise TypeError("findings must be a list")
    try:
        path = _cache_path(email, tenant_id)
        save_encrypted_json(path, {"cache_schema_version": IMAP_CACHE_SCHEMA_VERSION, "findings": [x for x in findings if isinstance(x, dict)]}, tenant_id=tenant_id)
        if os.name != "nt":
            try: os.chmod(path, 0o600)
            except OSError: pass
    except Exception: return



IMAP_SERVER = "imap.gmail.com"
IMAP_TIMEOUT_SECONDS = 30
# How many of the newest matching messages are inspected. Older registrations are missed when
# the mailbox has more matches than this; raise it (max 2000) for a deeper, slower scan.
DEFAULT_MAX_EMAILS = env_non_negative_int("IMAP_MAX_EMAILS", 500, 2000) or 500
IMAP_FETCH_BATCH_SIZE = env_non_negative_int("IMAP_FETCH_BATCH_SIZE", 50, 200) or 50
IMAP_MAX_HEADER_BYTES = 1024 * 1024
MIN_SUBJECT_SCORE = env_non_negative_int("IMAP_MIN_SUBJECT_SCORE", 50, 100) or 50

# Read-only fetch: BODY.PEEK never sets \\Seen, and the mailbox is opened with EXAMINE.
FETCH_SPEC = "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])"

# Gmail performs candidate filtering; Python applies the final weighted subject classifier.
SUBJECT_QUERY = (
    'subject:(welcome OR "selamat datang" OR "thank you" OR "terima kasih" OR '
    'verification OR verify OR verifikasi OR confirmation OR confirm OR konfirmasi OR '
    'registration OR registered OR registrasi OR pendaftaran OR register OR daftar OR '
    'activate OR activation OR aktivasi OR "account created" OR "akun dibuat" OR '
    'joined OR joining OR "all set" OR "getting started" OR "welcome aboard")'
)

SUBJECT_PATTERNS = {
    100: (
        "welcome to", "selamat datang", "thanks for joining", "thank you for joining",
        "terima kasih telah bergabung", "account created", "akun dibuat",
    ),
    90: (
        "verification", "verify", "verifikasi", "confirmation", "confirm your",
        "konfirmasi", "activate your account", "aktivasi akun", "activate account",
    ),
    80: (
        "registration", "registered", "registrasi", "pendaftaran", "registered successfully",
    ),
    60: (
        "welcome", "thank you", "terima kasih", "register", "daftar", "joining", "joined",
        "getting started", "welcome aboard", "all set", "activation", "aktivasi", "activate",
    ),
}


def mask_sensitive_subject(subject_text: str) -> str:
    """Melakukan redaksi pada Email, Nomor Telepon, OTP, PIN, atau Kode dari teks subjek."""
    if not subject_text:
        return ""

    # Specific patterns are masked before generic numeric codes.
    masked = re.sub(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', '***@***', subject_text)
    masked = re.sub(
        r'(?i)\b(otp|pin|kode|code|token|sandi|password)[\s:=]+[A-Za-z0-9_-]{4,12}\b',
        r'\1 ***',
        masked,
    )
    masked = re.sub(r'\bG-\d{4,8}\b', 'G-***', masked)
    masked = re.sub(r'\+?\b\d{9,15}\b', '***', masked)
    masked = re.sub(r'\b(?:\+62|62|0)[ \-]?\d{2,4}[ \-]?\d{3,4}[ \-]?\d{3,5}\b', '***', masked)
    return NUMERIC_CODE_PATTERN.sub('***', masked)


def select_all_mail_folder(mail: imaplib.IMAP4_SSL) -> str:
    """Mencoba memilih folder All Mail / Semua Email di Gmail (read-only)."""
    for folder in ('"[Gmail]/All Mail"', '"[Gmail]/Semua Email"', '"[Gmail]/Semua Pesan"'):
        status, _ = mail.select(folder, readonly=True)
        if status == "OK":
            logger.info("[IMAP] Selected folder: %s", folder)
            return folder

    logger.warning("[IMAP] All Mail folder not found. Falling back to INBOX.")
    mail.select("inbox", readonly=True)
    return "inbox"


def parse_sender_domain(from_header: str) -> str:
    """Root domain pengirim, atau "" untuk penyedia email gratis dan mailer massal.
    (sendgrid, amazonses, mailchimp, ...) yang bukan layanan itu sendiri."""
    _, address = parseaddr(from_header or "")
    if "@" not in address:
        return ""

    domain = address.rsplit("@", 1)[-1].lower().rstrip(".")
    if not domain or is_ignored_sender(domain):
        return ""
    return root_domain(domain)


def safe_decode_header(header_value: str) -> str:
    """Aman mengekstrak header email terlepas dari encoding."""
    if not header_value:
        return ""
    try:
        return str(make_header(decode_header(header_value)))
    except Exception:
        return str(header_value)


def score_subject(subject: str) -> int:
    """Return the strongest matching registration/service subject score."""
    normalized = " ".join(subject.casefold().split())
    return max(
        (score for score, patterns in SUBJECT_PATTERNS.items() if any(pattern in normalized for pattern in patterns)),
        default=0,
    )


def _iter_fetched_messages(msg_data: list) -> list[email.message.Message]:
    messages = []
    for response_part in msg_data:
        if not isinstance(response_part, tuple) or len(response_part) < 2:
            continue
        payload = response_part[1]
        if isinstance(payload, bytes):
            if len(payload) > IMAP_MAX_HEADER_BYTES:
                logger.warning("[IMAP] Skipping oversized header response: %d bytes.", len(payload))
                continue
            messages.append(email.message_from_bytes(payload))
    return messages


def _process_message(msg: email.message.Message, found_services: dict) -> bool:
    subject_raw = safe_decode_header(msg.get("Subject", ""))
    score = score_subject(subject_raw)
    if score < MIN_SUBJECT_SCORE:
        return False

    domain = parse_sender_domain(safe_decode_header(msg.get("From", "")))
    if not domain:
        return False

    subject = mask_sensitive_subject(subject_raw)[:60]
    current = found_services.get(domain)
    if current is None or score > current["score"]:
        found_services[domain] = {"score": score, "subject": subject}
    return True


def _fetch_batch(mail: imaplib.IMAP4_SSL, uid_batch: list[bytes]) -> list[email.message.Message]:
    if not uid_batch:
        return []
    uid_set = b",".join(uid_batch).decode("ascii", errors="ignore")
    status, msg_data = mail.uid("fetch", uid_set, FETCH_SPEC)
    if status != "OK":
        logger.warning("[IMAP] Batch FETCH failed for %d message(s).", len(uid_batch))
        return []
    return _iter_fetched_messages(msg_data)


def scan_gmail_inbox(
    email_address: str,
    app_password: str,
    max_emails: int | None = None,
    lang: str = "en",
) -> list[dict]:
    started_at = time.perf_counter()
    logger.info("[IMAP] Scanning target: %s", mask_email(email_address))
    max_emails = max_emails or DEFAULT_MAX_EMAILS
    max_emails = max(1, min(max_emails, 2000))
    found_services = {}
    candidate_count = inspected_count = matched_count = batch_count = 0
    credential = str(app_password).strip() if app_password else ""
    del app_password

    try:
        with imaplib.IMAP4_SSL(IMAP_SERVER, timeout=IMAP_TIMEOUT_SECONDS) as mail:
            mail.login(email_address, credential)
            del credential
            select_all_mail_folder(mail)

            escaped_query = SUBJECT_QUERY.replace('"', '\\"')
            status, messages = mail.uid("search", None, "X-GM-RAW", f'"{escaped_query}"')
            if status != "OK" or not messages or not messages[0]:
                return []

            email_ids = messages[0].split()[-max_emails:]
            candidate_count = len(email_ids)
            for start in range(0, candidate_count, IMAP_FETCH_BATCH_SIZE):
                batch = email_ids[start:start + IMAP_FETCH_BATCH_SIZE]
                batch_count += 1
                fetched_messages = _fetch_batch(mail, batch)
                inspected_count += len(fetched_messages)
                for msg in fetched_messages:
                    matched_count += _process_message(msg, found_services)

            results = []
            for domain, data in sorted(found_services.items()):
                logger.info("[IMAP] Found a matching service email for domain: %s", domain)
                results.append({
                    "name": domain.split(".")[0].capitalize(),
                    "domain": domain,
                    "source": t("source_imap", lang=lang),
                    "subject": data["subject"],
                })
            logger.info(
                "[IMAP] Stats: candidates=%d, headers_inspected=%d, matched=%d, services=%d, batches=%d, duration=%.2fs",
                candidate_count, inspected_count, matched_count, len(results), batch_count, time.perf_counter() - started_at,
            )
            return results
    except imaplib.IMAP4.error as imap_err:
        logger.error("[IMAP Error] IMAP authentication/command failed for [%s]", mask_email(email_address))
        raise RuntimeError(
            f"Gagal otentikasi IMAP: Pastikan App Password benar & IMAP aktif di Gmail. Detail: {imap_err}"
        )
    except Exception as exc:
        logger.error("[IMAP Error] Network or server issue: %s", type(exc).__name__)
        raise RuntimeError(f"IMAP Service Error: {exc}")
