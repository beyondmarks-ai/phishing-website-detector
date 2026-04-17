import unittest

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from phishing_detector.feature_extraction import build_feature_vector, normalize_url


class NormalizeUrlTests(unittest.TestCase):
    def test_adds_scheme(self):
        self.assertEqual(normalize_url("example.com"), "http://example.com")

    def test_rejects_invalid_input(self):
        with self.assertRaises(ValueError):
            normalize_url("")


class FeatureExtractionTests(unittest.TestCase):
    @patch("phishing_detector.feature_extraction.ENABLE_REPUTATION_LOOKUPS", False)
    def test_ip_address_host_detected(self):
        result = build_feature_vector("http://192.168.0.1/login")
        self.assertEqual(result.features["ip_address_host"], 1.0)

    @patch("phishing_detector.feature_extraction.ENABLE_REPUTATION_LOOKUPS", False)
    def test_shortener_detected(self):
        result = build_feature_vector("https://bit.ly/free")
        self.assertEqual(result.features["shortener_domain"], 1.0)

    @patch("phishing_detector.feature_extraction.ENABLE_REPUTATION_LOOKUPS", False)
    def test_suspicious_tld_detected(self):
        result = build_feature_vector("http://example.zip/login")
        self.assertEqual(result.features["suspicious_tld"], 1.0)

    @patch("phishing_detector.feature_extraction.ENABLE_REPUTATION_LOOKUPS", False)
    @patch("phishing_detector.feature_extraction._domain_age_days", return_value=10)
    @patch("phishing_detector.feature_extraction._fetch_html", return_value="")
    @patch("phishing_detector.feature_extraction.socket.gethostbyname", return_value="127.0.0.1")
    def test_recent_domain_adds_signal(self, _dns, _fetch, _age):
        result = build_feature_vector("https://example.com/login")
        self.assertEqual(result.features["domain_age_days"], 10.0)
        self.assertIn("Domain appears recently registered.", result.explanation_signals)

    def test_normalizes_creation_date_lists(self):
        from phishing_detector.feature_extraction import _coerce_creation_datetime

        older = datetime.now(timezone.utc) - timedelta(days=30)
        parsed = _coerce_creation_datetime([None, older])
        self.assertEqual(parsed, older)


if __name__ == "__main__":
    unittest.main()
