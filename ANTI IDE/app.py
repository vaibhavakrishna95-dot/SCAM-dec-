"""
SCAMSHIELD — Scam Detection Engine
Web Application Server (Flask)
Tagline: "Detect Suspicious Messages. Stay One Step Ahead."
"""

import os
import json
import time
from flask import Flask, request, jsonify, render_template

from scam_engine import engine, MODEL_PATH

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
METRICS_PATH = os.path.join(BASE_DIR, "models", "model_metrics.json")
DBSCAN_PATH = os.path.join(BASE_DIR, "models", "dbscan_sample.json")

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
app.config['MAX_CONTENT_LENGTH'] = 512 * 1024  # 512 KB max payload

START_TIME = time.time()


# -------------------------------------------------------------
# Frontend Page Routes
# -------------------------------------------------------------

@app.route("/")
def home():
    """Render Home page with product introduction, features, and quick demo."""
    return render_template("index.html")


@app.route("/detect")
def detect_dashboard():
    """Render the primary Scam Detection Dashboard."""
    return render_template("dashboard.html")


@app.route("/insights")
def ml_insights():
    """Render the ML Insights & DBSCAN Exploratory Clustering page."""
    return render_template("insights.html")


@app.route("/awareness")
def awareness():
    """Render the Cybersecurity Awareness and Safety Guide page."""
    return render_template("awareness.html")


@app.route("/about")
def about():
    """Render the About Project page with ML workflow, metrics, and architecture."""
    return render_template("about.html")


# -------------------------------------------------------------
# API Endpoints
# -------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint to monitor API status, uptime, and model state."""
    uptime_seconds = round(time.time() - START_TIME, 1)
    return jsonify({
        "status": "healthy",
        "service": "ScamShield Detection Engine",
        "version": "1.0.0",
        "uptime_seconds": uptime_seconds,
        "model_loaded": engine.model_loaded,
        "model_path": MODEL_PATH,
        "model_exists": os.path.exists(MODEL_PATH)
    }), 200


@app.route("/api/analyze", methods=["POST"])
def analyze_message():
    """
    POST /api/analyze
    Analyzes submitted text for spam, phishing, financial fraud, and suspicious URLs.
    Validates payload, executes ML inference & rule heuristics, and returns structured assessment.
    """
    if not request.is_json:
        return jsonify({
            "success": False,
            "error": "Request content must be application/json."
        }), 400

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Invalid or empty JSON body."
        }), 400

    raw_text = data.get("text", "")
    category = data.get("category", "sms")

    # Category validation
    allowed_categories = ["sms", "email", "url", "other"]
    if category not in allowed_categories:
        category = "other"

    # Input validation
    if not isinstance(raw_text, str) or not raw_text.strip():
        return jsonify({
            "success": False,
            "error": "Message text cannot be empty. Please provide text or URL to analyze."
        }), 400

    if len(raw_text) > 15000:
        return jsonify({
            "success": False,
            "error": "Message exceeds maximum allowed length of 15,000 characters."
        }), 413

    try:
        result = engine.analyze(raw_text, category=category)
        return jsonify(result), 200
    except Exception as e:
        # Avoid exposing raw server traces to user
        print(f"[-] API Exception during analysis: {e}")
        return jsonify({
            "success": False,
            "error": "An internal error occurred during text analysis. Please try again."
        }), 500


@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    """Return genuine model evaluation metrics and dataset statistics."""
    if os.path.exists(METRICS_PATH):
        try:
            with open(METRICS_PATH, "r", encoding="utf-8") as f:
                metrics = json.load(f)
            return jsonify({
                "success": True,
                "data": metrics
            }), 200
        except Exception as e:
            return jsonify({
                "success": False,
                "error": f"Failed reading metrics: {str(e)}"
            }), 500
    else:
        return jsonify({
            "success": False,
            "error": "Model metrics file not found. Run train_model.py first."
        }), 404


@app.route("/api/dbscan-sample", methods=["GET"])
def get_dbscan_sample():
    """Return DBSCAN exploratory clustering 2D projection and cluster points."""
    if os.path.exists(DBSCAN_PATH):
        try:
            with open(DBSCAN_PATH, "r", encoding="utf-8") as f:
                dbscan_data = json.load(f)
            return jsonify({
                "success": True,
                "data": dbscan_data
            }), 200
        except Exception as e:
            return jsonify({
                "success": False,
                "error": f"Failed reading DBSCAN data: {str(e)}"
            }), 500
    else:
        return jsonify({
            "success": False,
            "error": "DBSCAN sample data not found. Run train_model.py first."
        }), 404


# -------------------------------------------------------------
# Error Handlers
# -------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return render_template("base.html", not_found=True), 404


@app.errorhandler(413)
def request_entity_too_large(e):
    return jsonify({
        "success": False,
        "error": "Request entity too large. Maximum size is 512 KB."
    }), 413


@app.errorhandler(500)
def server_error(e):
    return jsonify({
        "success": False,
        "error": "Internal server error occurred."
    }), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting SCAMSHIELD on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
