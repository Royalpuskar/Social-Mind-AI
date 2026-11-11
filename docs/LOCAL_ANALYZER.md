# Local Message-Risk Analyzer

This module provides a deterministic, explainable first-pass triage of text messages. It runs locally with the Python standard library and makes no network requests.

## Run

From the repository root:

```bash
python -m unittest discover -s tests -v
```

Quick example:

```python
from socialmind_core import analyze_message

result = analyze_message("Urgent: send your OTP immediately")
print(result.to_dict())
```

## What it checks

- Requests for passwords, PINs, OTPs, and verification codes
- Urgency and account-suspension pressure
- Prize, fee, and payment bait
- Presence of URLs
- Secrecy and isolation language
- Possible authority impersonation language

The score is a transparent heuristic, not a trained model or a calibrated probability. A URL by itself is deliberately insufficient for a high-risk result. False positives and false negatives are possible.

## Privacy

The analyzer does not transmit message content. Use `redact_sensitive_data` before sharing examples for debugging. Redaction is best-effort and should be reviewed before publication.

## Safe-use boundary

This tool is for defensive education and personal triage. It does not visit links, identify senders, scan attachments, or prove that a message is legitimate. For financial or account-related requests, contact the organization through a phone number or website obtained independently.
