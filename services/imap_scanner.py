import os
import imaplib
import email
from email.header import decode_header
import re

from dotenv import load_dotenv

from utils.domains import is_ignored_sender, root_domain
from utils.envutil import env_non_negative_int
from utils.logging_setup import get_logger
from utils.privacy import NUMERIC_CODE_PATTERN, mask_email
from utils.translations import t

load_dotenv()
logger = get_logger("IMAPScanner")

IMAP_SERVER = "imap.gmail.com"
IMAP_TIMEOUT_SECONDS = 30
# How many of the newest matching messages are inspected. Older registrations are missed when
# the mailbox has more matches than this; raise it (max 2000) for a deeper, slower scan.
DEFAULT_MAX_EMAILS = env_non_negative_int("IMAP_MAX_EMAILS", 200, 2000) or 200

# Read-only fetch: BODY.PEEK never sets \Seen, and the mailbox is opened with EXAMINE.
FETCH_SPEC = "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])"

SUBJECT_QUERY = (
    'subject:(welcome OR verifikasi OR konfirmasi OR registration OR "terima kasih" OR "thank you" '
    'OR daftar OR pendaftaran OR register OR verification OR confirmation)'
)


def mask_sensitive_subject(subject_text: str) -> str:
    """Melakukan redaksi pada Email, Nomor Telepon, OTP, PIN, atau Kode dari teks subjek."""
    if not subject_text:
        return ""

    # 1. Masking format Email
    masked = re.sub(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', '***@***', subject_text)
    # 2. Masking Nomor Telepon Internasional/Lokal bersambung
    masked = re.sub(r'\+?\b\d{9,15}\b', '***', masked)
    # 3. Masking Nomor Telepon dengan pemisah spasi/strip
    masked = re.sub(r'\b(?:\+62|62|0)[ \-]?\d{2,4}[ \-]?\d{3,4}[ \-]?\d{3,5}\b', '***', masked)
    # 4. Masking angka 4-8 digit berdiri sendiri (tahun 19xx/20xx dipertahankan)
    masked = NUMERIC_CODE_PATTERN.sub('***', masked)
    # 5. Masking format Google Code
    masked = re.sub(r'\bG-\d{4,8}\b', 'G-***', masked)
    # 6. Masking string alfanumerik yang mengikuti kata kunci OTP/PIN/Code
    masked = re.sub(r'(?i)\b(otp|pin|kode|code|token|sandi|password)[\s:=]+[A-Za-z0-9_-]{4,12}\b', r'\1 ***', masked)

    return masked


def select_all_mail_folder(mail: imaplib.IMAP4_SSL) -> str:
    """Mencoba memilih folder All Mail / Semua Email di Gmail (read-only)."""
    all_mail_folders = [
        '"[Gmail]/All Mail"',
        '"[Gmail]/Semua Email"',
        '"[Gmail]/Semua Pesan"'
    ]

    for folder in all_mail_folders:
        status, _ = mail.select(folder, readonly=True)
        if status == "OK":
            logger.info(f"[IMAP] Berhasil memilih folder: {folder}")
            return folder

    logger.warning("[IMAP] Folder All Mail/Semua Email tidak ditemukan. Menggunakan INBOX.")
    mail.select("inbox", readonly=True)
    return "inbox"


def parse_sender_domain(from_header: str) -> str:
    """Root domain pengirim, atau "" untuk penyedia email gratis dan mailer massal
    (sendgrid, amazonses, mailchimp, ...) yang bukan layanan itu sendiri."""
    if not from_header:
        return ""

    match = re.search(r'<([^>]+)>', from_header)
    clean_email = match.group(1) if match else from_header.strip()

    if "@" not in clean_email:
        return ""

    domain = clean_email.split("@")[-1].strip().lower().rstrip(">")
    if not domain or is_ignored_sender(domain):
        return ""
    return root_domain(domain)


def safe_decode_header(header_value: str) -> str:
    """Aman mengekstrak header email terlepas dari encoding."""
    if not header_value:
        return ""
    decoded_parts = []
    try:
        for content, encoding in decode_header(header_value):
            if isinstance(content, bytes):
                decoded_parts.append(content.decode(encoding or "utf-8", errors="ignore"))
            elif isinstance(content, str):
                decoded_parts.append(content)
        return "".join(decoded_parts)
    except Exception:
        return str(header_value)


def scan_gmail_inbox(email_address: str, app_password: str, max_emails: int | None = None, lang: str = "id") -> list[dict]:
    logger.info(f"[IMAP] Scanning target: {mask_email(email_address)}")
    max_emails = max_emails or DEFAULT_MAX_EMAILS
    found_services = set()
    results = []
    credential = str(app_password).strip() if app_password else ""
    del app_password

    try:
        with imaplib.IMAP4_SSL(IMAP_SERVER, timeout=IMAP_TIMEOUT_SECONDS) as mail:
            mail.login(email_address, credential)
            del credential

            select_all_mail_folder(mail)

            escaped_query = SUBJECT_QUERY.replace('"', '\\"')
            status, messages = mail.search(None, 'X-GM-RAW', f'"{escaped_query}"')

            if status != "OK" or not messages[0]:
                return []

            email_ids = messages[0].split()[-max_emails:]
            for e_id in reversed(email_ids):
                _, msg_data = mail.fetch(e_id, FETCH_SPEC)
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])

                        subject = mask_sensitive_subject(safe_decode_header(msg.get("Subject", "")))
                        from_header = safe_decode_header(msg.get("From", ""))

                        domain = parse_sender_domain(from_header)
                        if domain and domain not in found_services:
                            logger.info(f"[IMAP] menemukan email sesuai filter dari layanan: {domain}")
                            found_services.add(domain)
                            results.append({
                                "name": domain.split(".")[0].capitalize(),
                                "domain": domain,
                                "source": t("source_imap", lang=lang),
                                "subject": subject[:60]
                            })
        return results
    except imaplib.IMAP4.error as imap_err:
        logger.error(f"[IMAP Error] Otentikasi/Perintah IMAP Gagal untuk [{mask_email(email_address)}]")
        raise RuntimeError(f"Gagal otentikasi IMAP: Pastikan App Password benar & IMAP aktif di Gmail. Detail: {imap_err}")
    except Exception as e:
        logger.error(f"[IMAP Error] Kendala jaringan atau server: {type(e).__name__}")
        raise RuntimeError(f"IMAP Service Error: {e}")
