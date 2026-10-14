# 🛡️ Phishing Email Detection & Awareness Dashboard

A **defensive, educational** tool that analyses an email's sender, URLs and language, produces an explainable 0-100 phishing risk score, classifies it (SAFE / LOW RISK / SUSPICIOUS / HIGH RISK / LIKELY PHISHING), stores history in SQLite and shows analytics plus awareness training in a Streamlit dashboard.

> **Safety:** uses only synthetic emails and reserved example domains. It never opens links, sends email or collects credentials. Do not use it against real people or systems.

## Features
- Paste email or upload a safe `.txt` / `.eml`
- URL analyzer (IP hosts, shorteners, TLDs, punycode, look-alike brands, `@` tricks, link-text mismatch)
- Sender analyzer (display-name spoofing, look-alike domains, Reply-To mismatch)
- Content analyzer (urgency, threats, credential requests, lures)
- Explainable findings + recommendations, defanged URLs
- Optional ML (TF-IDF + Logistic Regression) blended with rules
- SQLite history, analytics dashboard, CSV export, awareness page and quiz
- 15 unit tests

## Quick start (beginner steps)
1. Install Python 3.10+ and open a terminal in this folder.
2. Create an environment:
   - Windows: `python -m venv .venv` then `.venv\Scripts\activate`
   - macOS/Linux: `python3 -m venv .venv && source .venv/bin/activate`
3. `pip install -r requirements.txt`
4. Run tests: `python -m unittest discover -s tests`
5. (Optional ML) `python scripts/generate_dataset.py` then `PYTHONPATH=src python -m phishguard.ml_model`  (Windows PowerShell: `$env:PYTHONPATH="src"; python -m phishguard.ml_model`)
6. Start the app: `streamlit run app.py`

## Project structure
```
app.py                     Streamlit UI
src/phishguard/            models, config, url/sender/content analyzers, parser, scorer, database, ml_model
scripts/generate_dataset.py  synthetic dataset generator
data/sample_emails.csv     240 synthetic emails
tests/test_engine.py       unit tests
docs/                      ARCHITECTURE, REPORT, INTERVIEW_PREP
screenshots/               add your screenshots here
```

## How scoring works
Each rule adds points; each category (URL 40, SENDER 35, CONTENT 40) is capped; total is 0-100. Thresholds: 0-14 SAFE, 15-34 LOW RISK, 35-59 SUSPICIOUS, 60+ HIGH RISK. Tune in `src/phishguard/config.py`.

## Limitations
Heuristic rules can misfire; no SPF/DKIM/DMARC checks, attachment analysis or threat-intel lookups; synthetic data means reported accuracy is not real-world accuracy. See `docs/ARCHITECTURE.md`.


## License
MIT
