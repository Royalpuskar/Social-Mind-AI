# TraceGuard

A small, explainable, privacy-first URL triage tool for security learning.

TraceGuard checks a URL for suspicious characteristics and produces a transparent risk score with the exact signals that contributed to it. It is a **first-pass educational aid**, not a malware scanner, reputation service, or guarantee that a link is safe.

## Why it exists

People often receive shortened, misleading, or look-alike links in messages. TraceGuard helps a user slow down and inspect a URL before opening it, without sending the URL to a third-party service.

## Features

- Parse and normalize URLs safely.
- Flag non-HTTPS schemes, user-info fields, IP-address hosts, unusual ports, punycode, and deceptive host/path patterns.
- Explain every finding in plain language.
- Produce JSON output for scripting.
- Run locally; no network requests and no API key.
- Include unit tests and safe example inputs.

## Requirements

- Python 3.10+
- No third-party dependencies

## Quick start

From this directory:

```bash
python -m traceguard.cli "https://example.com/login"
python -m traceguard.cli "http://192.0.2.10/verify" --json
python -m unittest discover -s tests -v
```

Use reserved example domains and documentation IP ranges when experimenting. Do not visit suspicious links to test them.

## Example

```text
URL: http://192.0.2.10/verify
Risk: HIGH (65/100)
Findings:
- URL uses HTTP rather than HTTPS (+15)
- Host is an IP address rather than a domain name (+25)
- Path contains a credential-related term (+15)
```

Scores are heuristic indicators, not probabilities. A low score does not prove a URL is safe, and a high score does not prove malicious intent.

## Design and limitations

- The tool only analyzes the URL string; it does not resolve DNS, follow redirects, download files, inspect page content, or query threat-intelligence feeds.
- It does not store submitted URLs.
- Risk rules are intentionally visible and easy to audit.
- False positives and false negatives are possible. Treat unexpected links cautiously and verify important requests through a trusted, independently obtained channel.

## Project structure

```text
traceguard/
├── README.md
├── traceguard/
│   ├── __init__.py
│   ├── analyzer.py
│   └── cli.py
└── tests/
    └── test_analyzer.py
```

## Roadmap

- Add an optional browser-independent HTML report.
- Add carefully sourced domain reputation checks behind an explicit opt-in.
- Expand test coverage with benign and suspicious edge cases.

## License

MIT
