import os
import time
import imaplib
import email
from email.header import decode_header
import re
import logging
from dotenv import load_dotenv
from utils.translations import t

load_dotenv()
LOG_LEVEL = os.getenv("LOG_LEVEL", "NOTSET").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.NOTSET),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("IMAPScanner")

IMAP_SERVER = "imap.gmail.com"

def mask_email(email_str: str) -> str:
    """Strict PII Masking."""
    if "@" in email_str:
        parts = email_str.split("@")
        return f"{parts[0][:2]}***@{parts[1].split('.')[0][:1]}***.{parts[1].split('.')[-1]}"
    return "***"

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
    # 4. Masking angka 4-8 digit berdiri sendiri
    masked = re.sub(r'\b\d{4,8}\b', '***', masked)
    # 5. Masking format Google Code
    masked = re.sub(r'\bG-\d{4,8}\b', 'G-***', masked)
    # 6. Masking string alfanumerik yang mengikuti kata kunci OTP/PIN/Code
    masked = re.sub(r'(?i)\b(otp|pin|kode|code|token|sandi|password)[\s:=]+[A-Za-z0-9_-]{4,12}\b', r'\1 ***', masked)

    return masked

def select_all_mail_folder(mail: imaplib.IMAP4_SSL) -> str:
    """Mencoba memilih folder All Mail / Semua Email di Gmail."""
    all_mail_folders = [
        '"[Gmail]/All Mail"',
        '"[Gmail]/Semua Email"',
        '"[Gmail]/Semua Pesan"'
    ]

    for folder in all_mail_folders:
        status, _ = mail.select(folder)
        if status == "OK":
            logger.info(f"[IMAP] Berhasil memilih folder: {folder}")
            return folder

    logger.warning("[IMAP] Folder All Mail/Semua Email tidak ditemukan. Menggunakan INBOX.")
    mail.select("inbox")
    return "inbox"

def parse_sender_domain(from_header: str) -> str:
    """Mengekstrak root domain (TLD) agar tidak ada duplikasi subdomain."""
    if not from_header:
        return ""

    match = re.search(r'<([^>]+)>', from_header)
    clean_email = match.group(1) if match else from_header.strip()

    if "@" in clean_email:
        domain = clean_email.split("@")[-1].lower()

        if domain in ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "google.com"]:
            return ""

        parts = domain.split('.')
        if len(parts) >= 2:
            common_slds = {"co", "com", "net", "org", "ac", "go", "sch", "or", "web", "my", "biz"}
            if len(parts) >= 3 and parts[-2] in common_slds:
                domain = ".".join(parts[-3:])
            else:
                domain = ".".join(parts[-2:])
        return domain

    return ""

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

def scan_gmail_inbox(email_address: str, app_password: str, max_emails: int = 200, lang: str = "id") -> list[dict]:
    start_time = time.monotonic()
    logger.info("=== MEMULAI IMAP SCAN (%s) ===", mask_email(email_address))
    #logger.info(f"[IMAP] Scanning target: {mask_email(email_address)}")
    found_services = set()
    results = []

    # 1. FIX: Amankan memori dengan menghapus variabel asli `app_password` dari Local Scope
    _cred = str(app_password).strip() if app_password else ""
    del app_password

    try:
        with imaplib.IMAP4_SSL(IMAP_SERVER) as mail:
            mail.login(email_address, _cred)
            # 2. FIX: Hapus salinan memori sesegera mungkin
            del _cred

            select_all_mail_folder(mail)

            raw_query = 'subject:(welcome OR verifikasi OR konfirmasi OR registration OR "terima kasih" OR "thank you" OR daftar OR pendaftaran OR register OR verification OR confirmation)'

            # 3. FIX: Kompatibilitas Sintaks Python (Hindari mixed-quotes di dalam F-String)
            escaped_query = raw_query.replace('"', '\\"')
            status, messages = mail.search(None, 'X-GM-RAW', f'"{escaped_query}"')

            if status != "OK" or not messages[0]:
                #logger.info("=== IMAP SCAN SELESAI Dalam %.2f detik ===", time.monotonic() - start_time)
                return []

            email_ids = messages[0].split()[-max_emails:]
            for e_id in reversed(email_ids):
                _, msg_data = mail.fetch(e_id, "(BODY[HEADER.FIELDS (FROM SUBJECT DATE)])")
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
        #logger.info("=== IMAP SCAN SELESAI Dalam %.2f detik ===", time.monotonic() - start_time)
        return results
    except imaplib.IMAP4.error as imap_err:
        logger.error(f"[IMAP Error] Otentikasi/Perintah IMAP Gagal untuk [{mask_email(email_address)}]")
        raise RuntimeError(f"Gagal otentikasi IMAP: Pastikan App Password benar & IMAP aktif di Gmail. Detail: {imap_err}")
    except Exception as e:
        logger.error(f"[IMAP Error] Kendala jaringan atau server: {e}")
        raise RuntimeError(f"IMAP Service Error: {e}")
    finally:
        logger.info("=== IMAP SCAN SELESAI Dalam %.2f detik ===", time.monotonic() - start_time)
        # Memastikan tidak ada sisa kredensial di local scope meskipun terjadi Exception keras
        if '_cred' in locals():
            del _cred
        if 'app_password' in locals():
            del app_password