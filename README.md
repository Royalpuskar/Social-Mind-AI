# SocialMind AI — Digital Safety Research Lab

**A transparent, locally runnable social-engineering awareness prototype.** This repository explores rule-based scam-message triage, URL structure checks and safe handling of untrusted text.

**Status:** Working educational prototype, **not** an enterprise security product. No verified accuracy, user count, uptime SLA, or broad multi-model deployment is claimed.

## What is implemented

### Browser demonstration (`index.html`)
- Enter text or load synthetic scam-message examples.
- Run six explicit, local social-engineering indicators for credentials, urgency, payments/prizes, links, secrecy and impersonation wording.
- View an illustrative 0–100 indicator score, matched signals, and verification advice.
- Explore a separate static SQL example generator; output is an illustrative template and is **not** derived semantically from arbitrary inputs.
- Does not ask for any Anthropic/OpenAI key or transmit analysis text to a model provider.

Open `index.html` in a browser or serve it over localhost. Existing CSS and site sections include **roadmap concepts**, not guaranteed live features.

### Python message analyzer
`socialmind_core/analyzer.py`: six transparent rule patterns, risk levels, defensive advice and basic email/telephone redaction.

### TraceGuard URL analyzer
`projects/traceguard/traceguard/analyzer.py`: structural URL risk signals, including HTTP, user-info, IP hosts, punycode, abnormal ports, long hosts, many subdomains and suspicious path terms. It **does not** fetch URLs or consult reputation databases.

## Run tests

Python 3.11+ (standard library only):

```sh
python -m unittest discover -s tests -v
PYTHONPATH=projects/traceguard python -m unittest discover -s projects/traceguard/tests -v
```

On Windows PowerShell, replace the second line with:

```powershell
$env:PYTHONPATH="projects/traceguard"; python -m unittest discover -s projects/traceguard/tests -v
```

GitHub Actions verifies both Python suites and JavaScript syntax for the browser page.

## Security and research integrity

- A low risk score **does not** imply content is safe, truthful or non-malicious.
- The browser rules are English-focused and have no published precision/recall evaluation.
- No API key should be pasted into the browser app. Production integrations must keep credentials on a controlled backend with authentication, logging safeguards, throttling and billing limits.
- Only analyze material you are authorized to handle; avoid pasting passwords, payment credentials or private records.
- Roadmap feature descriptions and comparison ideas are **not statements of implementation**.

## Research directions

Expand and test with a documented, consented, representative dataset; publish false-positive/false-negative analysis, multilingual limitations, adversarial examples, reproducibility notebooks, and calibrated thresholds before claiming detection effectiveness.

Author: [Royalpuskar](https://github.com/Royalpuskar).
