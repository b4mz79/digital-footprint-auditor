# 🔍 Digital Footprint & OSINT Data Breach Auditor

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B.svg)](https://streamlit.io/)

**Language / Bahasa:** [English](README.md)  |  [Bahasa Indonesia](README_ID.md)

**Digital Footprint & OSINT Data Breach Auditor** is a personal digital footprint analysis and data breach auditing tool built with Python and Streamlit. This tool is designed to scan exposure across email accounts, phone number variations, and registered service footprints (via IMAP & OSINT) in a multi-layered approach. It then provides automated privacy risk analysis and generates a formal **Data Subject Request (DSR)** erasure draft based on **Indonesia's Personal Data Protection Act (UU PDP No. 27/2022)** as well as global standards.

---

## ✨ Key Features

* 📧 **Gmail IMAP Scanner**: Automatically identifies linked digital services by scanning confirmation and registration email subjects.
* 🕵️ **OSINT Account Checker**: Integrates *Holehe* to detect registered account presence across dozens of digital platforms.
* 🛡️ **Multi-Layer Breach Engine**:
* BreachDirectory DB API (Specialized for database dumps)
* Google Custom Search API & Scraper Fallback (`googlesearch-python`)
* Bing Search Scraper (via `BeautifulSoup`)
* Tavily AI Search API
* SearXNG MetaSearch & DuckDuckGo


* 📱 **Dynamic Phone Number Normalization**: Parses and searches national (`08xx`) and international (`+62xx`, `62xx`) phone formatting variations accurately.
* 🤖 **Multi-Model AI Risk Assessment**: Automatically analyzes privacy exposure levels using local or cloud LLMs (Google Gemini, Groq, OpenAI, and **Local Ollama** for privacy-first offline processing).
* 📜 **DSR Generator**: Generates formal Data Subject Request drafts for data erasure and destruction intended for data controllers.
* ⚡ **Caching & Noise Filter**: Built-in 12-hour TTL local caching system and domain noise filter to eliminate false positives.

---

## 🚀 Installation & Usage Guide

### 1. System Requirements

* Python 3.10 or higher.
* A Gmail account with an **App Password** configured (if using the Gmail Inbox Scan feature).

### 2. Clone Repository & Install Dependencies

```bash
# Clone repository
git clone https://github.com/b4mz79/digital-footprint-auditor.git
cd digital-footprint-auditor

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # For Linux/macOS
# venv\Scripts\activate   # For Windows

# Install required dependencies
pip install -r requirements.txt

```

### 3. Configure Environment Variables (`.env`)

Copy `.env.example` to `.env`:

```bash
cp .env.example .env

```

Open `.env` and fill in your API keys (the more complete your API setup, the better the search results):

```env
GOOGLE_API_KEY_1=your_gemini_key_here
GROQ_API_KEY=your_groq_key_here
OPENAI_API_KEY=your_openai_key_here
OLLAMA_MODEL=qwen2.5:3b
RAPIDAPI_KEY=your_rapidapi_key_here
GOOGLE_SEARCH_API_KEY=your_google_api_key_here
GOOGLE_CX_ID=your_custom_search_cx_here
TAVILY_API_KEY=your_tavily_key_here
DELAY_SECONDS=2

```

### 4. Run the Application

Launch the dashboard via Streamlit (or run `./run.sh` / `run.bat`):

```bash
streamlit run app.py

```

The application will open automatically in your local browser at `http://localhost:8501`.

---

## 🛠️ Breach Search Architecture

```text
[ Input Email & Phone ]
          │
          ├──> 1. Phone Normalization (08xx, +62xx, Spaces, Dashes)
          ├──> 2. Local Cache Verification (cache/breach/)
          └──> 3. Multi-Engine Iterative Scanning:
                   ├── BreachDirectory API
                   ├── Google API / Scraper Fallback
                   ├── Bing Scraper
                   ├── Tavily AI Search
                   ├── SearXNG MetaSearch
                   └── DuckDuckGo

```

---

## 🤝 Contributing

Contributions are warmly welcomed! If you'd like to add new OSINT modules, optimize scraper logic, or enhance the UI:

1. *Fork* this repository.
2. Create a new feature branch (`git checkout -b feature/CoolNewFeature`).
3. Commit your changes (`git commit -m 'Add Cool New Feature'`).
4. Push to your branch (`git push origin feature/CoolNewFeature`).
5. Open a **Pull Request (PR)**.
6. For detail about **Integration Test Suite**, please read [Integration Test Suite](Integration_Test_Suite.md)
7. For detail about how to integrate **Custom Breach Engine Extension**, please read [Custom Breach Engine Extension](Custom_Breach_Engine_Extension.md)

---

## ⚖️ License & Disclaimer

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

> **Disclaimer**: This tool was created strictly for educational purposes, personal privacy audits, and defensive OSINT research. Any unauthorized use against targets without prior consent is the sole responsibility of the end user.

