import phonenumbers
from phonenumbers import carrier, geocoder
import requests

def normalize_phone_number(phone_input: str, default_region: str = "ID") -> dict | None:
    """Mengubah input nomor HP ke format E.164 dan mengekstrak info dasar."""
    try:
        parsed_num = phonenumbers.parse(phone_input, default_region)
        if not phonenumbers.is_valid_number(parsed_num):
            return None

        e164_format = phonenumbers.format_number(parsed_num, phonenumbers.PhoneNumberFormat.E164)
        provider = carrier.name_for_number(parsed_num, "id")
        location = geocoder.description_for_number(parsed_num, "id")

        return {
            "e164": e164_format,
            "national": phonenumbers.format_number(parsed_num, phonenumbers.PhoneNumberFormat.NATIONAL),
            "carrier": provider or "Tidak diketahui",
            "location": location or "Indonesia"
        }
    except Exception as e:
        print(f"[Phone Parser Error] {e}")
        return None


def scan_phone_breaches(phone_e164: str, api_key: str = "") -> list:
    """Contoh pemanggilan API kebocoran data berdasarkan nomor HP (misal: LeakCheck/RapidAPI)."""
    found_leaks = []

    # Contoh integrasi API LeakCheck (atau RapidAPI / BreachDirectory)
    if api_key:
        try:
            url = f"https://leakcheck.io/api/v2/query/{phone_e164}"
            headers = {"X-API-Key": api_key}
            res = requests.get(url, headers=headers, timeout=10)
            if res.status_code == 200:
                data = res.json()
                for item in data.get("result", []):
                    found_leaks.append({
                        "service": item.get("source", "Unknown Leak Source"),
                        "source": "Phone Breach Database",
                        "sample_subject": f"Leak Date: {item.get('date', 'N/A')}"
                    })
        except Exception as e:
            print(f"[Phone Breach Error] {e}")

    return found_leaks