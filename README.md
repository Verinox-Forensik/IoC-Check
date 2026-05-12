# Verinox Forensik – Forensik Tool

A secure, privacy-first desktop application for batch-checking IPs and domains against the [VirusTotal API](https://www.virustotal.com/).  
Built with Python + tkinter. Runs on **macOS, Windows and Linux** without any hardcoded paths.

---

## Features

- 📂 Multi-format input: TXT, CSV, XLSX, XLSM, JSON, NDJSON, LOG, XML, HTML, TSV
- 🔍 Automatic IP & domain extraction via regex
- 🛡️ VirusTotal API integration (v3) with configurable rate limiting
- 📊 Results table with color-coded verdicts (clean / suspicious / malicious)
- 📤 Export to CSV or PDF – optionally AES-256 encrypted
- 🌐 UI language: German / English (switchable at runtime)
- 🔒 11 active security guarantees (see Security section below)

---

## Installation

```bash
git clone https://github.com/Verinox-Forensik/IoC-Check.git
cd IoC-Check
pip install -r requirements.txt
python main.py
```

> **Python 3.9+** required. On macOS use `python3 main.py`.

### Dependencies

```
requests>=2.31
openpyxl>=3.1
reportlab>=4.0
keyring>=24.0
pypdf>=4.0
pyzipper>=0.3.6
```

---

## VirusTotal API – Terms of Use

> ⚠️ **This tool requires your own VirusTotal API key.**  
> No API key is included or shared. Each user is responsible for complying with VirusTotal's Terms of Service.
>
> - The **free Public API** must **not** be used in commercial products or services.  
> - The **free Public API** is limited to 500 requests/day and 4 requests/minute.  
> - For commercial or business use, a [VirusTotal Premium API](https://docs.virustotal.com/reference/public-vs-premium-api) subscription is required.
>
> 👉 [Get your free API key](https://www.virustotal.com/gui/join-us) · [VirusTotal Terms of Service](https://docs.virustotal.com/docs/terms-of-service)

---

## Usage

1. Paste your [VirusTotal API key](https://www.virustotal.com/gui/my-apikey) into the key field
2. Select an input file (any supported format)
3. Choose scan targets (IPs, domains, or both) and rate limit
4. Click **Start** – results appear in real time
5. Export via the menu (CSV or PDF, with optional password)

A full user manual is included: [`MANUAL.txt`](MANUAL.txt)

---

## Security Highlights

| # | Feature | Implementation |
|---|---------|----------------|
| 1 | TLS cert pinning (TOFU) | stdlib `ssl` + SHA-256, stored in `~/.vt_analyzer_pins.json` |
| 2 | Proxy detection & warning | env-var + system proxy scan before every scan |
| 3 | Session-only API key mode | Key never written to disk |
| 4 | Clipboard guard | Auto-clears clipboard 30 s after key paste |
| 5 | SHA-256 file integrity | Input file hash logged before scan |
| 6 | Hash-chain audit log | Tamper-evident JSONL at `~/.vt_analyzer_audit.jsonl` |
| 7 | API key rotation reminder | Warns after 90 days (via OS keychain) |
| 8 | XLSM macro warning | Detected before file is opened |
| 9 | Encrypted export | AES-256 ZIP (CSV) / password PDF |
| 10 | Inactivity auto-lock | Configurable timeout clears the key from memory |
| 11 | Network allowlist | Only `www.virustotal.com` – any other host is blocked |

**Your API key never leaves your machine** and is never included in any export or log file.

---

## Runtime files (stored in your home directory)

| File | Purpose |
|---|---|
| `~/.vt_analyzer_audit.jsonl` | Tamper-evident audit log |
| `~/.vt_analyzer_pins.json` | TLS certificate pins |
| `~/.vt_analyzer_key.json` | Fallback key storage (if OS keychain unavailable) |

All paths resolve dynamically – no hardcoded absolute paths in the codebase.

---

## License

MIT License – see [LICENSE](LICENSE) for details.

---

*Developed by Verinox – Forensik Tool v2.0*
