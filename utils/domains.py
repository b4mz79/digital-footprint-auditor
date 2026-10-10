"""Domain helpers shared by the scanners and the AI service.

`root_domain` is a small heuristic (no network, no public-suffix list): it understands the
common `co.id` / `com.au` / `co.uk` style suffixes. It is good enough to group senders and to
compare a URL host with a service's own domain, and it is deliberately conservative.
"""
from __future__ import annotations

SECOND_LEVEL_SUFFIXES = {
    "co", "com", "net", "org", "edu", "gov", "ac", "go", "sch", "or", "web", "my", "biz",
    "mil", "ne", "gob", "gouv", "nom",
}

# Free-mail providers: a sender at these domains says nothing about a service.
FREE_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "icloud.com", "google.com", "proton.me", "protonmail.com",
}

# Bulk-mail infrastructure: the visible sender domain is the mailer, not the service.
MASS_MAILER_DOMAINS = {
    "sendgrid.net", "amazonses.com", "mailchimp.com", "mcsv.net", "mandrillapp.com",
    "sparkpostmail.com", "mailgun.org", "postmarkapp.com", "sendinblue.com", "brevo.com",
    "list-manage.com", "rsgsv.net", "constantcontact.com", "hubspotemail.net",
    "intercom-mail.com", "customeriomail.com", "klaviyomail.com", "exacttarget.com",
    "mktomail.com", "mailjet.com", "sendpulse.com", "e2ma.net", "cmail19.com", "cmail20.com",
}


def root_domain(host_or_domain: str) -> str:
    host = (host_or_domain or "").strip().lower().rstrip(".")
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return host
    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL_SUFFIXES and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def root_label(host_or_domain: str) -> str:
    """The registrable label, e.g. 'shopee' for 'help.shopee.co.id'."""
    return root_domain(host_or_domain).split(".")[0]


def display_name(host_or_domain: str) -> str:
    """Human-friendly service name from a domain: 'amazon.co.uk' -> 'Amazon'."""
    label = root_label(host_or_domain)
    return label.capitalize() if label else ""


def is_ignored_sender(domain: str) -> bool:
    root = root_domain(domain)
    return root in FREE_MAIL_DOMAINS or root in MASS_MAILER_DOMAINS
