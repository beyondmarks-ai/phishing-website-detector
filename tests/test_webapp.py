import unittest
from io import BytesIO
from unittest.mock import patch

from phishing_detector.inference import AnalysisResult
from phishing_detector.webapp import create_app


class WebAppTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_index_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Phishing Detector", response.data)
        self.assertIn(b"System Snapshot", response.data)
        self.assertIn(b"Current Training Context", response.data)
        self.assertIn(b"Recent Activity", response.data)

    @patch("phishing_detector.webapp.record_single_analysis")
    @patch("phishing_detector.webapp.analyze_url")
    def test_analyze_renders_result(self, mock_analyze, mock_record):
        mock_analyze.return_value = AnalysisResult(
            normalized_url="https://example.com",
            verdict="Legitimate",
            risk_score=12,
            probability=0.12,
            explanation_items=["No strong phishing indicators were triggered by the current checks."],
            warnings=[],
            features={
                "https_scheme": 1.0,
                "dns_resolves": 1.0,
                "shortener_domain": 0.0,
                "suspicious_tld": 0.0,
                "password_field_count": 0.0,
                "phishing_keyword_count_content": 0.0,
            },
            suspicious_signals=[],
            reassuring_signals=[],
            feature_sections=[],
        )
        response = self.client.post("/analyze", data={"url": "https://example.com"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Legitimate", response.data)
        self.assertIn(b"12/100", response.data)
        self.assertIn(b"View Full Analysis Detail", response.data)
        mock_record.assert_called_once()

    def test_invalid_url_returns_400(self):
        response = self.client.post("/analyze", data={"url": ""})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"URL is required.", response.data)

    @patch("phishing_detector.webapp.analyze_url")
    def test_analysis_detail_renders(self, mock_analyze):
        mock_analyze.return_value = AnalysisResult(
            normalized_url="https://example.com/login",
            verdict="Phishing",
            risk_score=82,
            probability=0.82,
            explanation_items=["URL uses a shortening service."],
            warnings=["DNS lookup failed."],
            features={"https_scheme": 0.0},
            suspicious_signals=["URL uses a shortening service."],
            reassuring_signals=["The URL uses a hostname instead of a raw IP address."],
            feature_sections=[
                {
                    "title": "URL Signals",
                    "rows": [{"label": "URL Length", "value": 25}],
                }
            ],
        )
        response = self.client.get("/analysis-detail?url=https://example.com/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Analysis Detail", response.data)
        self.assertIn(b"82/100", response.data)
        self.assertIn(b"URL Length", response.data)

    def test_analysis_detail_invalid_url_returns_400(self):
        response = self.client.get("/analysis-detail")
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"URL is required.", response.data)

    @patch("phishing_detector.webapp.analyze_url")
    def test_analysis_export_json_downloads_report(self, mock_analyze):
        mock_analyze.return_value = AnalysisResult(
            normalized_url="https://example.com/login",
            verdict="Phishing",
            risk_score=82,
            probability=0.82,
            explanation_items=["URL uses a shortening service."],
            warnings=["DNS lookup failed."],
            features={"https_scheme": 0.0},
            suspicious_signals=["URL uses a shortening service."],
            reassuring_signals=["The URL uses a hostname instead of a raw IP address."],
            feature_sections=[{"title": "URL Signals", "rows": [{"label": "URL Length", "value": 25}]}],
        )
        response = self.client.get("/analysis-export.json?url=https://example.com/login")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/json")
        self.assertIn(b'"verdict": "Phishing"', response.data)

    @patch("phishing_detector.webapp.analyze_url")
    def test_analysis_export_markdown_downloads_report(self, mock_analyze):
        mock_analyze.return_value = AnalysisResult(
            normalized_url="https://example.com/login",
            verdict="Phishing",
            risk_score=82,
            probability=0.82,
            explanation_items=["URL uses a shortening service."],
            warnings=["DNS lookup failed."],
            features={"https_scheme": 0.0},
            suspicious_signals=["URL uses a shortening service."],
            reassuring_signals=["The URL uses a hostname instead of a raw IP address."],
            feature_sections=[{"title": "URL Signals", "rows": [{"label": "URL Length", "value": 25}]}],
        )
        response = self.client.get("/analysis-export.md?url=https://example.com/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/markdown", response.mimetype)
        self.assertIn(b"# URL Analysis Report", response.data)
        self.assertIn(b"Risk score", response.data)

    def test_analysis_export_json_invalid_url_returns_400(self):
        response = self.client.get("/analysis-export.json")
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"URL is required.", response.data)

    @patch("phishing_detector.webapp.record_single_analysis")
    @patch("phishing_detector.webapp.analyze_url")
    def test_api_analyze_returns_json(self, mock_analyze, mock_record):
        mock_analyze.return_value = AnalysisResult(
            normalized_url="https://example.com/login",
            verdict="Phishing",
            risk_score=82,
            probability=0.82,
            explanation_items=["URL uses a shortening service."],
            warnings=["DNS lookup failed."],
            features={"https_scheme": 0.0},
            suspicious_signals=["URL uses a shortening service."],
            reassuring_signals=["The URL uses a hostname instead of a raw IP address."],
            feature_sections=[{"title": "URL Signals", "rows": [{"label": "URL Length", "value": 25}]}],
        )
        response = self.client.post("/api/analyze", json={"url": "https://example.com/login"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/json")
        self.assertIn(b'"verdict": "Phishing"', response.data)
        mock_record.assert_called_once()

    def test_api_analyze_invalid_url_returns_400(self):
        response = self.client.post("/api/analyze", json={"url": ""})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"URL is required.", response.data)

    @patch("phishing_detector.webapp.API_REQUIRE_AUTH", True)
    @patch("phishing_detector.webapp.API_AUTH_TOKEN", "secret-token")
    @patch("phishing_detector.webapp.analyze_url")
    def test_api_analyze_requires_auth_token(self, mock_analyze):
        mock_analyze.return_value = AnalysisResult(
            normalized_url="https://example.com/login",
            verdict="Phishing",
            risk_score=82,
            probability=0.82,
            explanation_items=["URL uses a shortening service."],
            warnings=[],
            features={"https_scheme": 0.0},
            suspicious_signals=["URL uses a shortening service."],
            reassuring_signals=[],
            feature_sections=[],
        )
        response = self.client.post("/api/analyze", json={"url": "https://example.com/login"})
        self.assertEqual(response.status_code, 401)

        response = self.client.post(
            "/api/analyze",
            json={"url": "https://example.com/login"},
            headers={"Authorization": "Bearer secret-token"},
        )
        self.assertEqual(response.status_code, 200)

    @patch("phishing_detector.webapp.API_RATE_LIMIT_MAX_REQUESTS", 1)
    @patch("phishing_detector.webapp.API_RATE_LIMIT_WINDOW_SECONDS", 60)
    @patch("phishing_detector.webapp.analyze_url")
    def test_api_analyze_rate_limit(self, mock_analyze):
        local_client = create_app().test_client()
        mock_analyze.return_value = AnalysisResult(
            normalized_url="https://example.com/login",
            verdict="Legitimate",
            risk_score=12,
            probability=0.12,
            explanation_items=["No strong phishing indicators were triggered by the current checks."],
            warnings=[],
            features={"https_scheme": 1.0},
            suspicious_signals=[],
            reassuring_signals=[],
            feature_sections=[],
        )
        response_one = local_client.post("/api/analyze", json={"url": "https://example.com/login"})
        self.assertEqual(response_one.status_code, 200)

        response_two = local_client.post("/api/analyze", json={"url": "https://example.com/login"})
        self.assertEqual(response_two.status_code, 429)

    @patch("phishing_detector.webapp.record_batch_run")
    @patch("phishing_detector.webapp.build_batch_summary")
    @patch("phishing_detector.webapp.analyze_batch_csv")
    def test_batch_analysis_renders_summary(self, mock_batch, mock_summary, mock_record):
        mock_batch.return_value = object()
        mock_summary.return_value = {
            "filename": "urls.csv",
            "total_rows": 2,
            "phishing_count": 1,
            "legitimate_count": 1,
            "error_count": 0,
            "rows": [
                {"row_number": 1, "input_url": "https://safe.example", "verdict": "Legitimate", "risk_score": 5, "top_signal": ""},
                {"row_number": 2, "input_url": "http://bad.example", "verdict": "Phishing", "risk_score": 91, "top_signal": "URL uses a shortening service."},
            ],
        }
        response = self.client.post(
            "/batch-analysis",
            data={"file": (BytesIO(b"url\nhttps://safe.example\n"), "urls.csv")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Batch Analysis", response.data)
        self.assertIn(b"urls.csv", response.data)
        self.assertIn(b"Phishing", response.data)
        mock_record.assert_called_once()

    def test_batch_analysis_missing_file_returns_400(self):
        response = self.client.post("/batch-analysis", data={}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Choose a CSV file to analyze.", response.data)

    @patch("phishing_detector.webapp.batch_result_to_csv", return_value="row_number,input_url\n1,https://safe.example\n")
    @patch("phishing_detector.webapp.analyze_batch_csv")
    def test_batch_analysis_export_downloads_csv(self, mock_batch, _mock_csv):
        mock_batch.return_value = object()
        response = self.client.post(
            "/batch-analysis-export",
            data={"file": (BytesIO(b"url\nhttps://safe.example\n"), "urls.csv")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/csv")
        self.assertIn(b"row_number,input_url", response.data)

    @patch("phishing_detector.webapp.load_training_report")
    @patch("phishing_detector.webapp.build_training_report_view")
    def test_training_report_renders(self, mock_build_view, mock_load_report):
        mock_load_report.return_value = {"model_name": "logistic_regression", "metrics": {}}
        mock_build_view.return_value = {
            "selected_model": "logistic_regression",
            "dataset_mode": "raw_url",
            "threshold": 0.5,
            "training_rows": 12,
            "test_rows": 3,
            "feature_count": 32,
            "data_paths": ["data/sample_urls.csv"],
            "model_rows": [],
        }
        response = self.client.get("/training-report")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Training Report", response.data)
        self.assertIn(b"logistic_regression", response.data)

    @patch("phishing_detector.webapp.load_training_report", side_effect=FileNotFoundError("missing"))
    def test_training_report_missing_returns_404(self, _mock_load_report):
        response = self.client.get("/training-report")
        self.assertEqual(response.status_code, 404)
        self.assertIn(b"missing", response.data)

    def test_settings_page_renders(self):
        response = self.client.get("/settings")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Settings", response.data)
        self.assertIn(b"Request Timeout", response.data)
        self.assertIn(b"User Agent", response.data)


if __name__ == "__main__":
    unittest.main()
