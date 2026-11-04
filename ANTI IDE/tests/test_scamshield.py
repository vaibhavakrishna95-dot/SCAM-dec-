"""
SCAMSHIELD — Automated Test Suite
Tests ML inference, heuristic threat engine, safe URL analysis, API validation,
fallback behavior when model is missing, and web routing.
"""

import unittest
import json
import os

from app import app
from scam_engine import ScamEngine, clean_text


class TestScamShieldEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = ScamEngine()
        cls.client = app.test_client()

    def test_clean_text_normalization(self):
        """Test that URLs, emails, currencies, and phone numbers normalize correctly."""
        raw = "Contact me at user@test.com or visit https://example.com for $500! Call 9876543210."
        cleaned = clean_text(raw)
        self.assertIn("emailaddr", cleaned)
        self.assertIn("urladdr", cleaned)
        self.assertIn("moneynum", cleaned)
        self.assertIn("phonenum", cleaned)

    def test_case_1_normal_legitimate_message(self):
        """Test Case 1: Normal, legitimate everyday message."""
        text = "Hey Sarah, are we still meeting in conference room B at 2 PM to review the project notes?"
        res = self.engine.analyze(text, category="other")
        self.assertTrue(res["success"])
        self.assertEqual(res["risk_level"], "Low")
        self.assertEqual(res["verdict"], "Not Detected as Spam")
        self.assertLess(res["risk_score"], 25)
        if res["model_confidence"]["available"]:
            self.assertLess(res["model_confidence"]["spam_probability"], 0.35)

    def test_case_2_promotional_spam_message(self):
        """Test Case 2: Promotional bulk spam message."""
        text = "URGENT! We are trying to contact you. Last weekends draw shows that you won a 1000 prize. Call now to claim."
        res = self.engine.analyze(text, category="sms")
        self.assertTrue(res["success"])
        self.assertIn(res["risk_level"], ["Medium", "High"])
        self.assertIn("Spam", res["verdict"])
        self.assertGreater(res["risk_score"], 40)

    def test_case_3_prize_lottery_scam(self):
        """Test Case 3: Message claiming the user won a prize."""
        text = "Congratulations! You have won £1,000,000 in the UK National Lottery. Contact agent to claim your cash prize."
        res = self.engine.analyze(text, category="sms")
        self.assertTrue(res["success"])
        self.assertEqual(res["risk_level"], "High")
        flag_ids = [sign["id"] for sign in res["warning_signs"]]
        self.assertIn("lottery_prize", flag_ids)

    def test_case_4_suspicious_payment_or_otp_request(self):
        """Test Case 4: Suspicious payment or OTP request (banking phish)."""
        text = "Dear customer, your bank account is suspended immediately. Please verify your OTP 749210 and enter password to restore access."
        res = self.engine.analyze(text, category="email")
        self.assertTrue(res["success"])
        self.assertEqual(res["risk_level"], "High")
        flag_ids = [sign["id"] for sign in res["warning_signs"]]
        self.assertIn("credentials_otp", flag_ids)
        self.assertIn("urgency", flag_ids)

    def test_case_5_phishing_message_with_url(self):
        """Test Case 5: Phishing-style message containing suspicious URL and IP address."""
        text = "Your FedEx parcel is detained. Pay customs fee now at http://192.168.1.100/login-verify-account to avoid return."
        res = self.engine.analyze(text, category="url")
        self.assertTrue(res["success"])
        self.assertEqual(res["risk_level"], "High")
        self.assertTrue(res["url_inspection"]["has_urls"])
        
        # Verify safe text heuristic found IP and credential keywords
        url_rules = [f["rule"] for f in res["url_inspection"]["url_risk_flags"]]
        self.assertTrue("IP_HOSTNAME" in url_rules or "CREDENTIAL_TARGETING_KEYWORD" in url_rules)

    def test_case_6_empty_and_invalid_input(self):
        """Test Case 6: Empty input, whitespace-only, and oversized input."""
        # Empty input via engine
        res_empty = self.engine.analyze("   ", category="sms")
        self.assertFalse(res_empty["success"])
        self.assertIn("empty", res_empty["error"].lower())

        # Empty input via Flask API
        resp = self.client.post("/api/analyze", json={"text": "   ", "category": "sms"})
        self.assertEqual(resp.status_code, 400)
        json_data = resp.get_json()
        self.assertFalse(json_data["success"])

        # Non-JSON payload
        resp_invalid = self.client.post("/api/analyze", data="plain text data")
        self.assertEqual(resp_invalid.status_code, 400)

        # Oversized payload (>15,000 characters)
        oversized_text = "A" * 16000
        resp_oversized = self.client.post("/api/analyze", json={"text": oversized_text})
        self.assertEqual(resp_oversized.status_code, 413)

    def test_case_7_missing_model_fallback(self):
        """Test Case 7: Engine operation when model file is missing."""
        fallback_engine = ScamEngine(model_path="non_existent_model_file.joblib")
        self.assertFalse(fallback_engine.model_loaded)
        self.assertIsNone(fallback_engine.model)

        # Engine still operates safely using rule heuristics
        res = fallback_engine.analyze("URGENT! You won lottery cash prize. Share your OTP now.")
        self.assertTrue(res["success"])
        self.assertEqual(res["risk_level"], "High")
        self.assertFalse(res["model_confidence"]["available"])
        self.assertIn("heuristic", res["model_confidence"]["interpretation"].lower())

    def test_api_health_and_metrics_endpoints(self):
        """Test API health check, metrics endpoint, and DBSCAN sample endpoint."""
        health_resp = self.client.get("/api/health")
        self.assertEqual(health_resp.status_code, 200)
        health_json = health_resp.get_json()
        self.assertEqual(health_json["status"], "healthy")
        self.assertTrue(health_json["model_loaded"])

        metrics_resp = self.client.get("/api/metrics")
        self.assertEqual(metrics_resp.status_code, 200)
        metrics_json = metrics_resp.get_json()
        self.assertTrue(metrics_json["success"])
        self.assertIn("Multinomial Naive Bayes", metrics_json["data"]["models"])

        dbscan_resp = self.client.get("/api/dbscan-sample")
        self.assertEqual(dbscan_resp.status_code, 200)
        dbscan_json = dbscan_resp.get_json()
        self.assertTrue(dbscan_json["success"])
        self.assertGreater(len(dbscan_json["data"]["points"]), 0)

    def test_frontend_page_routes(self):
        """Test that all frontend pages load with HTTP 200 status."""
        routes = ["/", "/detect", "/insights", "/awareness", "/about"]
        for r in routes:
            resp = self.client.get(r)
            self.assertEqual(resp.status_code, 200, f"Route {r} failed with {resp.status_code}")
            self.assertIn(b"SCAMSHIELD", resp.data)


if __name__ == "__main__":
    unittest.main()
