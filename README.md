# Ultimate Pro Phishing Analyzer

**Paste a link. Get a verdict.** A local Flask app that runs a URL through four reputation sources and renders one scored report in your browser.

This is a **defensive** tool: it analyses links you were sent. It does not create phishing pages.

---

## What it checks

| Source | What it contributes |
| --- | --- |
| **VirusTotal** | URL and domain detections across ~70 engines |
| **URLScan.io** | Live scan results, with a domain-search fallback for very long URLs |
| **WHOIS** | Domain age, registrar and registration window |
| **DNS** | A / MX / NS resolution, plus a hard `NXDOMAIN` verdict |

A dead domain is scored as **critical**, not "no data" â€” the usual behaviour of link checkers that quietly return clean when a domain has already been taken down.

## Features

- Weighted scoring with a plain-language verdict instead of a raw number
- Real-time progress per stage, streamed into the page
- Safe handling of TLS errors and unreachable hosts (no stack traces in the UI)
- Everything runs on `127.0.0.1` â€” the URL you paste is not stored

## Requirements

- Python 3.10+
- Free API keys for VirusTotal and URLScan.io

## Run

```bash
git clone https://github.com/hypersenseindia/-Ultimate-Pro-Phishing-Analyzer
cd -Ultimate-Pro-Phishing-Analyzer
pip install -r requirements.txt
python index.py
```

Then open <http://127.0.0.1:5000> and paste a URL.

## Security notice

`index.py` currently contains the API keys inline. **Rotate those keys** before reusing this project, and move them to environment variables:

```python
GOOGLE_KEY   = os.environ.get("GOOGLE_KEY", "")
VT_KEY       = os.environ.get("VT_KEY", "")
URLSCAN_KEY  = os.environ.get("URLSCAN_KEY", "")
```

Treat any key that has been pushed to a public repository as compromised.

## Legal

Use on links you have a legitimate reason to investigate. Do not use it to profile or harass anyone.
---

<p align="center">
  <sub>Built by <b>AG HYDRAXFF</b> &mdash; HYPERSENSEGLOBAL &middot;
  <a href="https://www.instagram.com/hydraxff_yt/">@hydraxff_yt</a></sub>
</p>