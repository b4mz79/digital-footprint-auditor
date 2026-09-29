import os
import imaplib
import email
from email.header import decode_header
import re
import logging
from dotenv import load_dotenv
from utils.translations import t

load_dotenv()
logger = logging.getLogger("IMAPScanner")

IMAP_SERVER = "imap.gmail.com"

def mask_email(email_str: str) -> str:
    """FIX: Strict PII Masking."""
    if "@" in email_str:
        parts = email_str.split("@")
        return f"{parts[0][:2]}***@{parts[1].split('.')[0][:1]}***.{parts[1].split('.')[-1]}"
    return "***"

def parse_sender_domain(from_header: str) -> str:
    match = re.search(r'<([^>]+)>', from_header)
    clean_email = match.group(1) if match else from_header.strip()
    if "@" in clean_email:
        domain = clean_email.split("@")[-1].lower()
        if domain not in ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "google.com"]:
            return domain
    return ""

def scan_gmail_inbox(email_address: str, app_password: str, max_emails: int = 200, lang: str = "id") -> list[dict]:
    found_services = set()
    results = []
    
    # FIX: Konversi password ke memori lokal secara ephemeral
    _cred = "".join(app_password)
    
    try:
        # FIX: Menggunakan Context Manager (didukung di Python 3.9+) agar koneksi tertutup otomatis saat crash
        with imaplib.IMAP4_SSL(IMAP_SERVER) as mail:
            mail.login(email_address, _cred)
            # Membersihkan variabel reference dengan cepat
            del _cred
            
            mail.select("inbox")
            search_query = '(OR SUBJECT "welcome" (OR SUBJECT "verifikasi" (OR SUBJECT "konfirmasi" (OR SUBJECT "registration" SUBJECT "terima kasih"))))'
            status, messages = mail.search(None, search_query)

            if status != "OK" or not messages[0]:
                return []

            email_ids = messages[0].split()[-max_emails:]
            for e_id in reversed(email_ids):
                _, msg_data = mail.fetch(e_id, "(BODY[HEADER.FIELDS (FROM SUBJECT DATE)])")
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        
                        subj_bytes, enc = decode_header(msg.get("Subject", ""))[0]
                        subject = subj_bytes.decode(enc or "utf-8", errors="ignore") if isinstance(subj_bytes, bytes) else subj_bytes
                        
                        from_bytes, enc = decode_header(msg.get("From", ""))[0]
                        from_header = from_bytes.decode(enc or "utf-8", errors="ignore") if isinstance(from_bytes, bytes) else from_bytes
                        
                        domain = parse_sender_domain(from_header)
                        if domain and domain not in found_services:
                            found_services.add(domain)
                            results.append({
                                "name": domain.split(".")[0].capitalize(),
                                "domain": domain,
                                "source": t("source_imap", lang=lang),
                                "sample_subject": subject[:60]
                            })
        return results
    except Exception as e:
        # Menghindari logging string kredensial
        logger.error(f"[IMAP Error] Gagal melakukan pemindaian: Autentikasi / Koneksi terputus.")
        raise RuntimeError("IMAP Service Error")
    finally:
        # Memastikan reference variabel GC dibersihkan
        if '_cred' in locals():
            del _cred