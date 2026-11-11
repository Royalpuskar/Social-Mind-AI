"""Static URL checks. No DNS lookups, network requests, or page fetching."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit, unquote


@dataclass(frozen=True)
class Finding:
    code: str
    message: str
    points: int


@dataclass(frozen=True)
class Analysis:
    url: str
    risk_score: int
    risk_level: str
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict:
        result = asdict(self)
        result["findings"] = [asdict(item) for item in self.findings]
        return result


SUSPICIOUS_TERMS = {
    "account": "account", "verify": "verification", "password": "password",
    "signin": "sign-in", "login": "login", "wallet": "wallet",
    "billing": "billing", "secure": "security-themed wording",
}


def analyze_url(raw_url: str) -> Analysis:
    """Analyze a URL string and return explainable heuristic findings."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ValueError("Please provide a non-empty URL.")
    candidate = raw_url.strip()
    if any(ord(ch) < 32 for ch in candidate):
        raise ValueError("URL must not contain control characters.")
    if "://" not in candidate:
        candidate = "https://" + candidate

    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        port = parsed.port  # Raises ValueError for malformed ports.
    except ValueError as exc:
        raise ValueError(f"Invalid URL: {exc}") from exc

    if parsed.scheme not in {"http", "https"} or not hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL with a hostname.")

    host = hostname.rstrip(".").lower()
    findings: list[Finding] = []

    def add(code: str, message: str, points: int) -> None:
        findings.append(Finding(code, message, points))

    if parsed.scheme == "http":
        add("http_scheme", "URL uses HTTP rather than HTTPS", 15)
    if parsed.username is not None or parsed.password is not None:
        add("userinfo", "URL contains user-info before the hostname", 25)

    try:
        ipaddress.ip_address(host)
    except ValueError:
        is_ip = False
    else:
        is_ip = True
    if is_ip:
        add("ip_host", "Host is an IP address rather than a domain name", 25)

    if "xn--" in host:
        add("punycode", "Hostname contains an internationalized (punycode) label", 15)
    if port is not None and port not in {80, 443}:
        add("unusual_port", f"URL uses a non-standard web port ({port})", 10)
    if len(host) > 45:
        add("long_host", "Hostname is unusually long", 10)
    if host.count(".") >= 4:
        add("many_subdomains", "Hostname has an unusually large number of subdomains", 10)
    if re.search(r"\d{4,}", host):
        add("long_digit_run", "Hostname contains a long run of digits", 10)

    decoded_path = unquote(parsed.path).lower()
    matched = sorted({label for term, label in SUSPICIOUS_TERMS.items()
                      if term in decoded_path or term in host})
    if matched:
        add("sensitive_terms", "URL contains sensitive-action wording: " + ", ".join(matched), 15)

    score = min(100, sum(item.points for item in findings))
    level = "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH"
    return Analysis(raw_url.strip(), score, level, tuple(findings))
