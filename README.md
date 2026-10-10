# 🔍 Digital Footprint & OSINT Data Breach Auditor

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B.svg)](https://streamlit.io/)

**Language / Bahasa:** [English](README.md) | [Bahasa Indonesia](README_ID.md)

Digital Footprint & OSINT Data Breach Auditor is a Python and Streamlit application for reviewing a person's digital footprint using consent-based email, phone, OSINT, and breach-search inputs. It combines discovered-service evidence with optional contextual security-publication evidence and AI-assisted privacy-risk analysis. It can also draft a **Data Subject Request (DSR)** for review by the data subject before contacting a data controller.

The application is intended for personal privacy audits, authorized defensive research, and educational use. It does not guarantee that every exposed account or breach will be found.

---

## ✨ Key Features

- **Gmail IMAP Scanner** — identifies services from matching registration, confirmation, and related email messages. Gmail access requires an App Password when enabled.
- **OSINT Account Checker** — uses Holehe to check account-presence signals across supported services.
- **Multi-engine breach search** — can use BreachDirectory (RapidAPI), Have I Been Pwned (HIBP), Google Custom Search, Google/Bing/DuckDuckGo search fallbacks, Tavily, and an optionally configured SearXNG instance. Provider availability depends on configuration and external service limits.
- **Phone-number normalization** — generates bounded national and international variants for configured-region searches.
- **Evidence normalization and provenance** — represents scan observations as structured evidence, retaining source and evidence characteristics for downstream review.
- **Optional security-publication enrichment** — when enabled and configured with a Firecrawl API key, searches for contextual security-publication material using normalized domains. Contextual publication evidence is not proof that the user's account or domain was compromised.
- **Evidence URL verification** — checks accessibility of evidence URLs already present in records. This is an accessibility check, not a security audit of the destination website or domain.
- **AI-assisted privacy-risk analysis** — validates model output and applies deterministic evidence-based safeguards. Supported provider flow can include Google Gemini, Groq, OpenAI, and local Ollama; provider order and local-only behavior are configurable.
- **Data Subject Request (DSR) drafts** — generates editable request text; users should verify the facts, applicable law, and recipient before sending.
- **Encrypted local cache and tenant-aware cache identities** — reduces repeated requests while separating configured tenant cache identities.
- **Add-On runtime** — supports manifest-based optional extensions. See the [Add-On Tech Guide](docs/ADDON_TECH_GUIDE.md) and the [sample Add-On](addons/just-sample/).

## 🔐 Privacy and Limitations

- Use the application only with data you own or are explicitly authorized to audit.
- Configure credentials in a local `.env` file. Never commit API keys, Gmail credentials, or other secrets.
- Scan results are dependent on provider coverage, search indexing, rate limits, and available credentials. A successful scan with no findings does **not** prove that no exposure exists.
- Contextual security articles may discuss a service or domain generally; they must not be treated as direct evidence about an individual account.
- AI output is decision support, not a legal conclusion or a guarantee of security status. Review findings and generated DSR drafts before acting.
- Local Ollama can keep model inference local when configured accordingly, but external scanning/enrichment providers still make network requests when enabled.

---

## 🚀 Installation and Usage

### 1. Requirements

- Python 3.10 or newer.
- Git.
- A Gmail App Password if you plan to use Gmail IMAP scanning.
- API credentials only for the optional providers you intend to use.
- A running local Ollama service if you intend to use the local model.

### 2. Clone and install

```bash
git clone https://github.com/b4mz79/digital-footprint-auditor.git
cd digital-footprint-auditor

python -m venv venv
# Linux/macOS
source venv/bin/activate
# Windows PowerShell
# .\venv\Scripts\Activate.ps1

pip install -r requirements.txt
pip install -r requirements-test.txt  # only if you plan to run tests
```

### 3. Configure `.env`

Copy the example file and edit it locally:

```bash
cp .env.example .env
```

At minimum, set `PII_PEPPER_KEY` to a randomly generated secret of at least 32 characters. One way to generate a suitable value is:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Then configure only the providers you want to use. Common settings include:

| Setting | Purpose |
|---|---|
| `GOOGLE_API_KEY_1` … `GOOGLE_API_KEY_6`, `GEMINI_API_KEY`, `GOOGLE_API_KEY` | Gemini credentials / key rotation |
| `GROQ_API_KEY`, `OPENAI_API_KEY` | Cloud AI providers |
| `LLM_PROVIDER_ORDER` | AI provider order |
| `LLM_LOCAL_ONLY=true` | Prevent cloud AI calls and use local Ollama only |
| `OLLAMA_HOST`, `OLLAMA_MODEL` | Local Ollama endpoint and model |
| `RAPIDAPI_KEY` | BreachDirectory provider |
| `HIBP_API_KEY` | Have I Been Pwned breach metadata |
| `GOOGLE_SEARCH_API_KEY`, `GOOGLE_CX_ID` | Google Custom Search |
| `TAVILY_API_KEY`, `SEARXNG_INSTANCE_URL` | Optional breach-search providers |
| `FIRECRAWL_API_KEY` | Optional contextual security-publication enrichment |
| `TENANT_ID` | Local tenant/cache identity |

See [`.env.example`](.env.example) for all supported settings and defaults. Do not paste secrets into issue reports or commit your `.env` file.

### 4. Run the application

Use the launcher for your operating system, or start Streamlit directly:

```bash
# Linux / macOS
./run.sh

# Or run directly
python -m streamlit run app.py
```

On Windows, run `run.bat` from Command Prompt or PowerShell. The dashboard normally listens on `http://localhost:8501`.

The launchers support reset modes. Review their behavior before using a reset mode because it removes selected local cache/build artifacts and may stop a process listening on port 8501.

### Docker (contributors)

For a containerized development environment and a separate Docker-based test runner, see the [Docker workflow for contributors](docs/DOCKER.md). The Compose setup binds the dashboard to localhost and keeps secrets and persisted cache data out of the image.

---

## 🛠️ Breach Search Flow

```text
Email / Phone Input
        |
        v
Input Validation and Phone Normalization
        |
        v
Per-Target / Per-Engine Cache
        |
        v
Configured Breach Search Engines
        |
        v
Normalized Findings + Engine Status
        |
        v
Evidence Pipeline / UI / AI Analysis
```

The breach scanner uses a bounded worker queue, per-engine rate limiting, circuit-breaker and health tracking, retry/cooldown handling, response-size limits, and normalized findings. Engine status distinguishes a successful empty result from a skipped, rate-limited, timed-out, or failed engine.

## 🧪 Tests

Install test dependencies and run the suite:

```bash
pip install -r requirements-test.txt
python -m pytest
```

See [Integration Test Suite](docs/Integration_Test_Suite.md) for coverage and contributor guidance.

## 🧩 Extending the Project

- To integrate a built-in breach-search provider, follow [Custom Breach Engine Extension](docs/Custom_Breach_Engine_Extension.md). A breach engine is registered in the core scanner plan; it is not the same thing as a ZIP-installed Add-On.
- To develop an optional Add-On, follow the [Add-On Tech Guide](docs/ADDON_TECH_GUIDE.md) ([Bahasa Indonesia](docs/ADDON_TECH_GUIDE_ID.md)).
- Before opening a Pull Request, run the tests and include any relevant regression tests.

## 🤝 Contributing

1. Fork the repository.
2. Create a feature branch.
3. Make a focused change and add or update tests.
4. Run `python -m pytest`.
5. Open a Pull Request describing the change, test results, and any configuration or migration implications.

## ⚖️ License and Disclaimer

This project is licensed under the [MIT License](LICENSE).

> **Disclaimer:** This tool is intended for educational use, personal privacy audits, and authorized defensive OSINT research. Do not scan data or targets without appropriate authorization. Search results can be incomplete or inaccurate; users are responsible for validating findings and deciding what action to take.
