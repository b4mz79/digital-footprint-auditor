import imaplib
import email
from email.header import decode_header
import re

IMAP_SERVER = "imap.gmail.com"

def parse_sender_domain(from_header: str) -> str:
    """Mengekstrak nama domain atau nama layanan dari header From."""
    # Ekstrak email di dalam tanda <...>
    match = re.search(r'<([^>]+)>', from_header)
    clean_email = match.group(1) if match else from_header.strip()

    if "@" in clean_email:
        domain = clean_email.split("@")[-1].lower()
        # Filter domain penyedia email umum agar tidak muncul sebagai layanan
        common_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "google.com"]
        if domain not in common_providers:
            return domain
    return ""

def scan_gmail_inbox(email_address: str, app_password: str, max_emails: int = 200) -> list[dict]:
    """
    Memindai folder Inbox Gmail untuk menemukan email pendaftaran/selamat datang.
    """
    found_services = set()
    results = []

    try:
        # Koneksi SSL aman
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(email_address, app_password)
        mail.select("inbox")

        # Kata kunci pencarian email registrasi
        search_query = '(OR OR OR OR SUBJECT "welcome" SUBJECT "verifikasi" SUBJECT "konfirmasi" SUBJECT "registration" SUBJECT "terima kasih")'
        status, messages = mail.search(None, search_query)

        if status != "OK" or not messages[0]:
            mail.logout()
            return []

        email_ids = messages[0].split()
        # Ambil email terbaru sejumlah max_emails
        email_ids = email_ids[-max_emails:]

        for e_id in reversed(email_ids):
            _, msg_data = mail.fetch(e_id, "(BODY[HEADER.FIELDS (FROM SUBJECT DATE)])")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])

                    # Decode Subject
                    subject, encoding = decode_header(msg.get("Subject", ""))[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(encoding or "utf-8", errors="ignore")

                    # Decode From
                    from_header, encoding = decode_header(msg.get("From", ""))[0]
                    if isinstance(from_header, bytes):
                        from_header = from_header.decode(encoding or "utf-8", errors="ignore")

                    domain = parse_sender_domain(from_header)
                    if domain and domain not in found_services:
                        found_services.add(domain)
                        results.append({
                            "name": domain.split(".")[0].capitalize(),
                            "domain": domain,
                            "source": "Gmail IMAP Scan",
                            "sample_subject": subject[:60]
                        })

        mail.logout()
        return results

    except Exception as e:
        raise Exception(f"Gagal memindai Gmail: {str(e)}")