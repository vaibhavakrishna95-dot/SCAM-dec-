"""
SCAMSHIELD — Core Scam Detection Engine
Integrates the trained Machine Learning pipeline with rule-based heuristic threat detection,
safe text-based URL analysis, risk scoring, and security advisory generation.
"""

import os
import re
import math
from urllib.parse import urlparse
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "scam_model.joblib")


def clean_text(text: str) -> str:
    """Preprocess text: lowercasing, standardizing URLs/phones/numbers, removing junk."""
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r'https?://\S+|www\.\S+', ' urladdr ', text)
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', ' emailaddr ', text)
    text = re.sub(r'[$£€₹]\s*\d+([.,]\d+)?', ' moneynum ', text)
    text = re.sub(r'\b\d{10,12}\b', ' phonenum ', text)
    text = re.sub(r'\b\d+\b', ' numbertoken ', text)
    text = re.sub(r'[^\w\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


class ScamEngine:
    def __init__(self, model_path: str = MODEL_PATH):
        self.model_path = model_path
        self.model = None
        self.model_loaded = False
        self.load_model()

        # Known URL Shortener Domains
        self.url_shorteners = {
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
            "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at"
        }

        # High-risk / Spam-frequent TLDs
        self.suspicious_tlds = {
            "xyz", "top", "work", "loan", "click", "cam", "link", "gq",
            "cf", "ml", "ga", "tk", "rest", "buzz", "fit", "surf", "icu"
        }

        # Threat Rules & Pattern Dictionary
        self.warning_rules = [
            {
                "id": "urgency",
                "category": "High Pressure & Urgency",
                "patterns": [
                    r"\b(urgent|urgently|immediately|action required|act now|hurry|limited time)\b",
                    r"\b(within \d+ (hours?|mins?|minutes?)|expire[sd]? today|deadline|final notice)\b",
                    r"\b(suspended|blocked|locked|terminated|deactivated|frozen|legal action)\b",
                    r"\b(warrant|arrest|court summons|penalt(y|ies)|fine)\b"
                ],
                "severity": "medium",
                "desc": "Uses urgent or threatening language to induce panic and force hasty decisions."
            },
            {
                "id": "credentials_otp",
                "category": "Credential & OTP Solicitation",
                "patterns": [
                    r"\b(otp|one[\s-]time[\s-]password|verification code|security code)\b",
                    r"\b(cvv|pin|atm pin|password|passcode|secret key|seed phrase)\b",
                    r"\b(share your otp|confirm your pin|enter your password|verify credentials)\b"
                ],
                "severity": "high",
                "desc": "Requests secret authentication data (OTP, PIN, or password) which legitimate organizations never ask for."
            },
            {
                "id": "lottery_prize",
                "category": "Prize & Unsolicited Reward Claim",
                "patterns": [
                    r"\b(congratulations|you have won|winner|won a prize|cash prize|claim your prize)\b",
                    r"\b(selected as winner|lottery|jackpot|free gift card|free voucher|reward points)\b",
                    r"\b(claim now|exclusive prize|jackpot prize|free iphone)\b"
                ],
                "severity": "high",
                "desc": "Claims you won a lottery, prize, or gift card that you never entered."
            },
            {
                "id": "financial_advance_fee",
                "category": "Advance Fee & Suspicious Payment",
                "patterns": [
                    r"\b(processing fee|advance fee|registration charge|customs fee|refundable deposit)\b",
                    r"\b(send money|wire transfer|western union|moneygram|crypto|bitcoin|usdt|eth)\b",
                    r"\b(gift card payment|paytm|upi transfer|pay advance|overdue balance)\b"
                ],
                "severity": "high",
                "desc": "Demands payment via untraceable methods (gift cards, wire transfer, cryptocurrency) or asks for advance processing fees."
            },
            {
                "id": "impersonation",
                "category": "Authority & Brand Impersonation",
                "patterns": [
                    r"\b(bank manager|customs officer|tax department|income tax|irs|cyber cell)\b",
                    r"\b(fedex|dhl|courier delivery|parcel held|package detained|postal service)\b",
                    r"\b(support desk|customer care|security department|fraud detection team)\b"
                ],
                "severity": "medium",
                "desc": "Impersonates authorities, courier delivery services, tax officers, or bank personnel."
            },
            {
                "id": "fake_job",
                "category": "Fake Job & Work From Home Scheme",
                "patterns": [
                    r"\b(work from home|part[\s-]time job|earn \d+ (per day|daily|weekly))\b",
                    r"\b(like youtube videos|data entry job|no experience needed|instant payout)\b",
                    r"\b(telegram task|daily income|hiring urgently|simple online tasks)\b"
                ],
                "severity": "high",
                "desc": "Offers unrealistic easy income for simple tasks (video liking, data entry, review rating)."
            },
            {
                "id": "action_links",
                "category": "Call-To-Action Link / Phone",
                "patterns": [
                    r"\b(click here|click on this link|open this link|tap here|visit link)\b",
                    r"\b(call immediately|call on \+?\d{8,12}|contact whatsapp)\b"
                ],
                "severity": "low",
                "desc": "Directs user to click unverified links or dial unfamiliar helpline numbers."
            }
        ]

    def load_model(self):
        """Safely load trained model pipeline with fallback handling."""
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                self.model_loaded = True
                print(f"[+] ScamEngine loaded ML model from: {self.model_path}")
            except Exception as e:
                print(f"[-] Failed to load model from {self.model_path}: {e}")
                self.model = None
                self.model_loaded = False
        else:
            print(f"[-] Model file not found at: {self.model_path}. Running in rule-engine fallback mode.")
            self.model = None
            self.model_loaded = False

    def inspect_url_safely(self, text: str) -> dict:
        """
        Pure text-based, non-executing heuristic inspection of URLs found in text or passed directly.
        Does NOT make any HTTP network connections to target domains.
        """
        # Extract potential URLs
        url_regex = r'(https?://[^\s<>"]+|www\.[^\s<>"]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s<>"]*)?)'
        found_urls = re.findall(url_regex, text)

        if not found_urls:
            return {"has_urls": False, "urls_inspected": [], "url_risk_flags": []}

        inspected_urls = []
        url_flags = []

        for raw_url in found_urls[:5]:  # limit to first 5
            norm_url = raw_url
            if not norm_url.startswith(("http://", "https://")):
                norm_url = "http://" + norm_url

            parsed = urlparse(norm_url)
            hostname = (parsed.hostname or "").lower()
            path = (parsed.path or "").lower()

            flags = []

            # 1. IP address in hostname
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
                flags.append({
                    "rule": "IP_HOSTNAME",
                    "severity": "high",
                    "detail": f"Direct IP address hostname detected ({hostname}) rather than a verified registered domain."
                })

            # 2. URL Shortener detection
            if hostname in self.url_shorteners:
                flags.append({
                    "rule": "URL_SHORTENER",
                    "severity": "medium",
                    "detail": f"URL shortener domain used ({hostname}) which hides the real destination."
                })

            # 3. Suspicious / Low-reputation TLD
            tld = hostname.split(".")[-1] if "." in hostname else ""
            if tld in self.suspicious_tlds:
                flags.append({
                    "rule": "SUSPICIOUS_TLD",
                    "severity": "medium",
                    "detail": f"Uncommon or high-abuse top level domain (.{tld}) detected."
                })

            # 4. Multiple Subdomains / Lookalike Spoofing
            parts = hostname.split(".")
            if len(parts) > 3:
                flags.append({
                    "rule": "EXCESSIVE_SUBDOMAINS",
                    "severity": "medium",
                    "detail": f"Unusually deep subdomain chain ({hostname}) often used to mimic legitimate brand names."
                })

            # 5. Phishing / Credential Keywords in Path or Hostname
            phish_keywords = ["login", "verify", "signin", "account-update", "banking", "secure", "wallet", "kyc", "auth"]
            for kw in phish_keywords:
                if kw in hostname or kw in path:
                    flags.append({
                        "rule": "CREDENTIAL_TARGETING_KEYWORD",
                        "severity": "high",
                        "detail": f"Authentication keyword '{kw}' found in URL, typical of phishing credential harvesters."
                    })
                    break

            # 6. Punycode / Internationalized Domain Name spoofing
            if "xn--" in hostname:
                flags.append({
                    "rule": "PUNYCODE_HOMOGRAPH",
                    "severity": "high",
                    "detail": "Punycode (xn--) detected; possible homograph attack mimicking known characters."
                })

            inspected_urls.append({
                "raw_url": raw_url,
                "domain": hostname,
                "flags": flags
            })
            url_flags.extend(flags)

        return {
            "has_urls": True,
            "urls_inspected": inspected_urls,
            "url_risk_flags": url_flags
        }

    def detect_warning_signs(self, text: str, category: str) -> list:
        """Scan text against security threat patterns and return detected warning signs."""
        detected_signs = []
        lower_text = text.lower()

        for rule in self.warning_rules:
            matched_snippets = []
            for pat in rule["patterns"]:
                matches = re.finditer(pat, lower_text, re.IGNORECASE)
                for m in matches:
                    matched_snippets.append(m.group(0))

            if matched_snippets:
                # Deduplicate matched terms
                unique_snippets = list(dict.fromkeys(matched_snippets))[:3]
                detected_signs.append({
                    "id": rule["id"],
                    "title": rule["category"],
                    "severity": rule["severity"],
                    "description": rule["desc"],
                    "triggers": unique_snippets
                })

        return detected_signs

    def evaluate_risk(self, ml_prob: float, warning_signs: list, url_inspection: dict, category: str):
        """
        Integrates ML model probability with rule-based heuristics.
        CRITICAL RULE: A normal-looking message must not automatically be declared safe.
        Distinguishes model probability from rule flags to produce final Risk Assessment.
        """
        # Calculate heuristic risk score (0 to 100)
        heuristic_score = 0
        high_sev_count = sum(1 for sign in warning_signs if sign["severity"] == "high")
        med_sev_count = sum(1 for sign in warning_signs if sign["severity"] == "medium")
        low_sev_count = sum(1 for sign in warning_signs if sign["severity"] == "low")

        url_high_count = sum(1 for f in url_inspection.get("url_risk_flags", []) if f["severity"] == "high")
        url_med_count = sum(1 for f in url_inspection.get("url_risk_flags", []) if f["severity"] == "medium")

        heuristic_score += high_sev_count * 30
        heuristic_score += med_sev_count * 15
        heuristic_score += low_sev_count * 5
        heuristic_score += url_high_count * 35
        heuristic_score += url_med_count * 15

        heuristic_score = min(100, heuristic_score)

        # ML confidence contribution (if model available)
        if ml_prob is not None:
            ml_score = ml_prob * 100
            # Integrated score combines ML with rule triggers
            integrated_score = (0.55 * ml_score) + (0.45 * heuristic_score)
        else:
            # Fallback when ML model is absent
            integrated_score = heuristic_score

        integrated_score = min(100, max(0, round(integrated_score, 1)))

        # Determine Risk Level and Category
        # If any high severity warning exists (e.g. OTP theft, fraudulent fee), risk must be at least Medium
        if integrated_score >= 60 or high_sev_count >= 1 or url_high_count >= 1 or (ml_prob is not None and ml_prob >= 0.75):
            risk_level = "High"
            predicted_verdict = "Spam / Suspicious"
        elif integrated_score >= 25 or med_sev_count >= 1 or url_med_count >= 1 or (ml_prob is not None and ml_prob >= 0.35):
            risk_level = "Medium"
            predicted_verdict = "Suspicious Content Detected" if integrated_score >= 40 else "Proceed With Caution"
        else:
            risk_level = "Low"
            predicted_verdict = "Not Detected as Spam"

        # Generate plain-English explanation
        explanation_points = []
        if ml_prob is not None:
            if ml_prob >= 0.75:
                explanation_points.append(
                    f"The machine-learning classification model identified language patterns strongly characteristic of spam and scam campaigns ({ml_prob*100:.1f}% confidence)."
                )
            elif ml_prob >= 0.35:
                explanation_points.append(
                    f"The machine-learning model detected moderate similarity to promotional or bulk spam messages ({ml_prob*100:.1f}% confidence)."
                )
            else:
                explanation_points.append(
                    f"The machine-learning model classified the primary text structure as consistent with standard legitimate messages (spam likelihood {ml_prob*100:.1f}%)."
                )

        if high_sev_count > 0 or url_high_count > 0:
            explanation_points.append(
                f"Critical red flags were discovered: {high_sev_count + url_high_count} high-severity warning trigger(s), including direct credential/payment requests or deceptive link characteristics."
            )
        elif med_sev_count > 0 or url_med_count > 0:
            explanation_points.append(
                f"Heuristic review found {med_sev_count + url_med_count} moderate warning sign(s), such as artificial urgency or authority impersonation."
            )
        else:
            if risk_level == "Low":
                explanation_points.append(
                    "No prominent scam signatures, emergency threats, or unsolicited credential requests were discovered in this text."
                )

        explanation = " ".join(explanation_points)

        # Generate actionable safety recommendations
        recommendations = []
        if high_sev_count > 0 or "credentials_otp" in [s["id"] for s in warning_signs]:
            recommendations.append("NEVER share OTPs, PINs, passwords, or CVVs. Legitimate organizations and banks will never ask you to disclose them.")
        if url_inspection.get("has_urls"):
            recommendations.append("DO NOT click links in unverified messages. Manually type the official company web address directly into your browser.")
        if "lottery_prize" in [s["id"] for s in warning_signs]:
            recommendations.append("Do not pay advance processing fees or registration fees to claim a prize; legitimate rewards never require upfront payments.")
        if "financial_advance_fee" in [s["id"] for s in warning_signs]:
            recommendations.append("Refrain from sending cryptocurrency, wire transfers, or gift card codes to unfamiliar parties.")
        if "urgency" in [s["id"] for s in warning_signs]:
            recommendations.append("Take time to verify claims independently. Scammers create fake urgency to prevent you from double-checking.")
        if risk_level in ["High", "Medium"]:
            recommendations.append("Block the sender and report the message to your service provider or official cybercrime reporting portal.")
        else:
            recommendations.append("Always verify sender authenticity through known independent channels before taking action.")

        return {
            "verdict": predicted_verdict,
            "risk_level": risk_level,
            "risk_score": integrated_score,
            "ml_spam_probability": round(float(ml_prob), 4) if ml_prob is not None else None,
            "explanation": explanation,
            "recommendations": recommendations
        }

    def analyze(self, text: str, category: str = "sms") -> dict:
        """
        Main analysis method: runs text cleaning, ML inference, URL inspection,
        warning sign extraction, and integrated risk assessment.
        """
        if not text or not text.strip():
            return {
                "success": False,
                "error": "Message text is empty. Please enter text to analyze."
            }

        raw_text = text.strip()
        cleaned_text = clean_text(raw_text)

        # ML Model Inference
        ml_prob = None
        ml_prediction = None
        if self.model_loaded and self.model is not None:
            try:
                # predict_proba returns [prob_ham, prob_spam]
                probs = self.model.predict_proba([cleaned_text])[0]
                ml_prob = float(probs[1])  # probability of spam
                ml_prediction = int(self.model.predict([cleaned_text])[0])
            except Exception as e:
                print(f"[-] Inference error: {e}")
                ml_prob = None

        # Rule-based warning signs
        warning_signs = self.detect_warning_signs(raw_text, category)

        # URL safe heuristic inspection
        url_inspection = self.inspect_url_safely(raw_text)

        # Risk assessment synthesis
        risk_data = self.evaluate_risk(ml_prob, warning_signs, url_inspection, category)

        return {
            "success": True,
            "input_category": category,
            "char_count": len(raw_text),
            "word_count": len(raw_text.split()),
            "verdict": risk_data["verdict"],
            "risk_level": risk_data["risk_level"],
            "risk_score": risk_data["risk_score"],
            "model_confidence": {
                "available": bool(ml_prob is not None),
                "spam_probability": risk_data["ml_spam_probability"],
                "model_name": type(self.model.named_steps.get('clf', self.model)).__name__ if self.model_loaded and hasattr(self.model, 'named_steps') else "MultinomialNB (Baseline)",
                "interpretation": f"{risk_data['ml_spam_probability']*100:.1f}% likelihood of being spam/scam pattern" if ml_prob is not None else "ML model unavailable; relying on heuristic threat engine"
            },
            "warning_signs": warning_signs,
            "warning_signs_count": len(warning_signs),
            "url_inspection": url_inspection,
            "explanation": risk_data["explanation"],
            "recommendations": risk_data["recommendations"]
        }


# Singleton instance for easy import in Flask
engine = ScamEngine()
