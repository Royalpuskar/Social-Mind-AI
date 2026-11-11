"""A small, explainable safety analyzer that runs without network access.

This is a triage aid, not a guarantee that content is safe or malicious.
It deliberately uses transparent indicators rather than claiming AI accuracy.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any


@dataclass(frozen=True)
class AnalysisResult:
    risk_score: int
    risk_level: str
    indicators: tuple[str, ...]
    recommended_actions: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["indicators"] = list(self.indicators)
        result["recommended_actions"] = list(self.recommended_actions)
        return result


_PATTERNS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("credential_request", re.compile(r"\b(password|passcode|one[- ]time code|otp|verification code|pin)\b", re.I), 28),
    ("urgent_pressure", re.compile(r"\b(urgent|immediately|within \d+ minutes|act now|account will be (?:closed|suspended))\b", re.I), 18),
    ("payment_or_prize_bait", re.compile(r"\b(claim your prize|you have won|processing fee|send (?:the )?payment|gift card)\b", re.I), 22),
    ("suspicious_link", re.compile(r"(?:https?://|www\.)[^\s]+", re.I), 8),
    ("secrecy_or_isolation", re.compile(r"\b(do not tell anyone|keep this secret|don't contact your bank)\b", re.I), 18),
    ("impersonation_language", re.compile(r"\b(CEO| IT support|bank security|government officer)\b", re.I), 8),
)

def analyze_message(message: str) -> AnalysisResult:
    """Score common social-engineering signals in plain text.

    Scores are capped at 100. Multiple indicators may co-occur. A link alone
    is not proof of maliciousness; users should verify it independently.
    """
    if not isinstance(message, str):
        raise TypeError("message must be a string")
    if not message.strip():
        raise ValueError("message must not be empty")

    indicators: list[str] = []
    score = 0
    for name, pattern, weight in _PATTERNS:
        if pattern.search(message):
            indicators.append(name)
            score += weight

    score = min(score, 100)
    if score >= 60:
        level = "high"
        actions = ("Do not click links or send money", "Do not share passwords or verification codes", "Verify through an independently obtained official contact")
    elif score >= 25:
        level = "medium"
        actions = ("Pause before responding", "Verify the sender using another channel", "Inspect links without opening them")
    else:
        level = "low"
        actions = ("No strong known warning pattern detected", "Still verify unexpected requests independently")
    return AnalysisResult(score, level, tuple(indicators), actions)


def redact_sensitive_data(text: str) -> str:
    """Mask common email addresses and phone-like digit sequences before sharing."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    text = re.sub(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[REDACTED_EMAIL]", text, flags=re.I)
    return re.sub(r"(?<!\w)(?:\+?\d[\d ()-]{7,}\d)(?!\w)", "[REDACTED_PHONE]", text)
