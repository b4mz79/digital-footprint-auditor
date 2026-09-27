import trio
from holehe.core import import_submodules, reach_function

async def scan_email_footprint(email: str) -> list[dict]:
    """
    Memindai pendaftaran email di berbagai platform menggunakan Holehe.
    """
    modules = import_submodules()
    results = []

    # Fungsi async pembungkus untuk Trio runner
    async def run_checks():
        for module in modules:
            try:
                out = []
                await reach_function(module, email, out)
                for item in out:
                    if item.get("exists"):
                        results.append({
                            "domain": item.get("domain"),
                            "name": item.get("name"),
                            "rate_limit": item.get("rate_limit", False)
                        })
            except Exception:
                continue

    # Holehe menggunakan Trio untuk async concurrency
    trio.run(run_checks)
    return results