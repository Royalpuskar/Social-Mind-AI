import unittest

from traceguard.analyzer import analyze_url


class AnalyzeUrlTests(unittest.TestCase):
    def test_plain_https_domain_has_no_findings(self):
        result = analyze_url("https://example.com")
        self.assertEqual(result.risk_score, 0)
        self.assertEqual(result.risk_level, "LOW")

    def test_http_ip_and_login_path_are_flagged(self):
        result = analyze_url("http://192.0.2.10/login")
        codes = {finding.code for finding in result.findings}
        self.assertTrue({"http_scheme", "ip_host", "sensitive_terms"} <= codes)
        self.assertEqual(result.risk_level, "HIGH")

    def test_user_info_is_flagged(self):
        result = analyze_url("https://user:pass@example.com/")
        self.assertIn("userinfo", {item.code for item in result.findings})

    def test_missing_scheme_is_normalized_for_analysis(self):
        result = analyze_url("example.com")
        self.assertEqual(result.risk_score, 0)

    def test_empty_input_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_url("   ")

    def test_malformed_port_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_url("https://example.com:99999")


if __name__ == "__main__":
    unittest.main()
