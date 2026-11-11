import unittest

from socialmind_core import analyze_message
from socialmind_core.analyzer import redact_sensitive_data


class AnalyzerTests(unittest.TestCase):
    def test_empty_message_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_message("   ")

    def test_credential_and_urgency_raise_risk(self):
        result = analyze_message("URGENT: send your OTP immediately or account will be closed")
        self.assertIn("credential_request", result.indicators)
        self.assertIn("urgent_pressure", result.indicators)
        self.assertGreaterEqual(result.risk_score, 25)
        self.assertIn(result.risk_level, {"medium", "high"})

    def test_link_alone_is_not_high_risk(self):
        result = analyze_message("Please read this article: https://example.com")
        self.assertEqual(result.risk_level, "low")

    def test_score_is_capped(self):
        result = analyze_message("urgent send payment gift card OTP password keep this secret https://x.test")
        self.assertLessEqual(result.risk_score, 100)

    def test_result_is_json_friendly(self):
        result = analyze_message("Hello")
        self.assertIsInstance(result.to_dict()["indicators"], list)

    def test_redaction(self):
        value = redact_sensitive_data("Email me at test@example.com or call +1 202 555 0147")
        self.assertNotIn("test@example.com", value)
        self.assertIn("[REDACTED_EMAIL]", value)
        self.assertIn("[REDACTED_PHONE]", value)


if __name__ == "__main__":
    unittest.main()
