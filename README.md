# SCAM-dec-[README.md](https://github.com/user-attachments/files/34383185/README.md)
# SCAMSHIELD — Scam Detection Engine

> **Tagline:** *“Detect Suspicious Messages. Stay One Step Ahead.”*

![Python Version](https://img.shields.io/badge/Python-3.13%2B-blue)
![Framework](https://img.shields.io/badge/Framework-Flask%203.1-black)
![ML Engine](https://img.shields.io/badge/ML-scikit--learn-orange)
![Accuracy](https://img.shields.io/badge/Model%20Accuracy-98.74%25-brightgreen)
![Dataset](https://img.shields.io/badge/Dataset-UCI%20SMS%20Spam-purple)

---

## 1. Project Overview

**SCAMSHIELD** is an end-to-end Machine Learning and Cyber Threat Intelligence web application engineered to detect, classify, and explain suspicious communications. It analyzes SMS messages, phishing emails, fraudulent job offers, fake lottery prize claims, urgent OTP/password harvesting attempts, and malicious URLs.

### Why Dual-Layer Architecture?
In modern social engineering, single-method tools fail:
1. **Machine Learning Alone:** May miss novel zero-day phishes or urgent credential demands disguised with polite phrasing.
2. **Rule Heuristics Alone:** Cannot catch evolving vocabulary patterns or subtle syntactic distributions.

ScamShield combines a **supervised NLP classification pipeline (TF-IDF + Multinomial Naive Bayes / Logistic Regression)** with an **unsupervised DBSCAN density clustering explorer**, a **deep heuristic rule engine**, and a **zero-execution URL threat inspector**.

---

## 2. Key Capabilities & Features

1. **Scam Detection Dashboard (`/detect`):**
   - Ingests SMS, emails, website links, and other text up to 15,000 characters.
   - Quick 1-click representative samples (Lottery Scam, Bank OTP Alert, Fake Courier Link, Job Offer Scam, Normal Delivery Alert, Personal Meeting).
   - Radar scanning animation during inference.
   - Outputs:
     - **Verdict:** `Spam / Suspicious` vs `Not Detected as Spam`
     - **Calibrated Risk Level:** `Low`, `Medium`, `High` with visual risk gauge (0–100)
     - **Model Confidence Score:** Probability breakdown from `predict_proba`
     - **Discovered Red Flags:** High-, medium-, and low-severity warnings with exact text triggers
     - **Plain-English Explanation:** Clear breakdown of why the verdict was issued
     - **Tailored Security Recommendations:** Actionable defense checklist
2. **Safe Text-Based URL Inspector:**
   - Dissects URLs without initiating HTTP connections or executing scripts.
   - Flags raw IP hostnames, URL shorteners (bit.ly, tinyurl), high-risk TLDs (.xyz, .top), and deceptive credential keywords (`/login`, `/banking`, `/verify`).
3. **Exploratory DBSCAN Clustering (`/insights`):**
   - 2D canvas scatter visualizer of 500 stratified messages projected via TruncatedSVD.
   - Interactive hover tooltips showing message snippets, cluster IDs, and anomaly tags.
   - Isolates **Noise (-1)** points to detect uncoordinated zero-day attacks and dense clusters representing coordinated spam campaigns.
4. **Verified Model Benchmark Metrics:**
   - Transparent evaluation on 1,034 held-out test records with **zero data leakage**.
   - Side-by-side comparison between **Multinomial Naive Bayes** (Accuracy: 98.74%, F1: 94.86%) and **Logistic Regression** (Accuracy: 98.45%, Precision: 100%).
   - Interactive confusion matrix display.
5. **Scam Awareness Guide (`/awareness`):**
   - 6 detailed threat dossiers on modern fraud types.
   - Interactive "Spot the Red Flag" self-assessment quiz.
   - Emergency incident response checklist for victims of suspected scams.
6. **Session Scan History:**
   - Client-side history drawer allowing 1-click reloading of previous scans.
   - Zero-retention privacy guarantee (no user text stored on server disks).

---

## 3. Machine Learning Architecture & Benchmark Results

### Dataset Provenance
Trained on the **UCI Machine Learning Repository SMS Spam Collection** (Almeida & Hidalgo).
- **Raw records:** 5,574
- **Deduplicated & purified records:** 5,171 (4,518 Ham, 653 Spam)
- **Split:** Stratified 80% train (4,135 samples) / 20% test (1,034 samples)
- **Feature Extraction:** Sublinear TF-IDF (1,2-ngrams, min_df=2, max 6,000 features) fitted strictly on the training partition.

### Verified Evaluation Results (Held-Out Test Set)

| Model Architecture | Accuracy | Precision | Recall | F1-Score | Status |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Multinomial Naive Bayes** | **98.74%** | **98.36%** | **91.60%** | **94.86%** | **Selected Production Pipeline** |
| **Logistic Regression (C=5.0)** | **98.45%** | **100.00%** | **87.79%** | **93.50%** | Evaluated Baseline |

### Confusion Matrix (MultinomialNB on 1,034 Test Samples)
- **True Negatives (Legitimate Correctly Passed):** 901
- **False Positives (Legitimate Flagged as Spam):** 2
- **False Negatives (Spam Slipped Past):** 11
- **True Positives (Spam Correctly Caught):** 120

---

## 4. Project Directory Structure

```
ANTI IDE/
├── app.py                      # Flask web application and REST API endpoints
├── train_model.py              # ML data ingestion, training, evaluation & DBSCAN script
├── scam_engine.py              # Core engine: ML inference, threat heuristics, URL inspector
├── requirements.txt            # Python dependencies
├── README.md                   # Complete documentation and run instructions
├── data/
│   └── SMSSpamCollection       # UCI benchmark dataset
├── models/
│   ├── scam_model.joblib       # Serialized production pipeline (TF-IDF + Naive Bayes)
│   ├── model_metrics.json      # Genuine evaluation metrics & confusion matrix
│   └── dbscan_sample.json      # 2D projected DBSCAN sample coordinates
├── templates/
│   ├── base.html               # Master cyber-themed navigation and layout
│   ├── index.html              # Hero, problem overview, and live demo card
│   ├── dashboard.html          # Main scam detection dashboard & history drawer
│   ├── insights.html           # Interactive DBSCAN canvas & benchmark comparison
│   ├── awareness.html          # Educational guide, threat dossiers & quiz
│   └── about.html              # Whitepaper, architecture, limitations & roadmap
├── static/
│   ├── css/
│   │   └── style.css           # Custom cyber-navy stylesheet and animations
│   └── js/
│       ├── main.js             # Global utilities & API health check
│       ├── dashboard.js        # Dashboard state, sample loader, scan history
│       └── insights.js         # Interactive DBSCAN HTML5 canvas renderer
└── tests/
    └── test_scamshield.py      # Automated test suite (10 unit/integration tests)
```

---

## 5. Installation & Execution Instructions

### Prerequisites
- Python 3.10 to 3.13
- Windows PowerShell or command prompt / VS Code terminal

### Step 1: Clone / Open Project Folder in VS Code
Open the directory `c:\Users\HP\Desktop\ANTI IDE` in VS Code or navigate to it in PowerShell:
```powershell
cd "c:\Users\HP\Desktop\ANTI IDE"
```

### Step 2: Install Dependencies
```powershell
python -m pip install -r requirements.txt
```

### Step 3: Train or Re-Train the Model (Optional)
The trained model (`models/scam_model.joblib`), metrics, and DBSCAN samples are already generated. To re-train or download fresh data at any time, run:
```powershell
python train_model.py
```

### Step 4: Run Automated Tests
Verify all 10 unit and integration test cases:
```powershell
python -m unittest tests/test_scamshield.py
```
*Expected output: `Ran 10 tests ... OK`*

### Step 5: Start the Flask Web Server
```powershell
python app.py
```

### Step 6: Access the Web Application
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 6. Demonstration & Testing Guide

When demonstrating the project for reviews, academic presentations, or testing:

1. **Home Page (`/`):**
   - Review the problem statement, 98.7% test accuracy badge, and 3-step architecture.
   - Click **"Analyze Suspicious Message"** or use the interactive preview card.
2. **Detection Dashboard (`/detect`):**
   - Click **"Lottery Prize Scam"** sample -> Click **"Analyze Message"**: Observe high risk, 100% ML confidence, and Lottery Prize flag.
   - Click **"Urgent Bank OTP"** sample -> Click **"Analyze Message"**: Observe high risk, OTP theft flag, and urgency warnings.
   - Click **"Fake Courier Link"** sample -> Click **"Analyze Message"**: Observe safe URL inspection flags detecting raw IP hostname and suspicious subdomains.
   - Click **"Normal Personal Chat"** sample -> Click **"Analyze Message"**: Observe Low risk, 0% spam probability, and clean verdict.
   - Inspect the **Recent Scans** history drawer: click any past scan to reload it into the input area.
3. **ML Insights & DBSCAN (`/insights`):**
   - Hover over the 2D cluster scatter plot to inspect coordinates, cluster numbers, and message snippets.
   - Toggle **"Outliers / Noise"** to show DBSCAN's anomaly detection capabilities.
   - Review the verified comparison table between Naive Bayes and Logistic Regression and the confusion matrix.
4. **Scam Awareness (`/awareness`):**
   - Take the interactive **"Spot the Red Flag"** quiz to demonstrate user education.
   - Review the Emergency Incident Response triage steps.
5. **About Page (`/about`):**
   - Read the transparent disclosure regarding Google Colab authentication boundaries and the machine learning pipeline whitepaper.

---

## 7. REST API Reference

### Health Check
- **Endpoint:** `GET /api/health`
- **Response:**
  ```json
  {
    "status": "healthy",
    "service": "ScamShield Detection Engine",
    "model_loaded": true,
    "uptime_seconds": 12.4
  }
  ```

### Analyze Message
- **Endpoint:** `POST /api/analyze`
- **Request Body:**
  ```json
  {
    "text": "URGENT: Your account is suspended. Verify OTP 9821 now.",
    "category": "sms"
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "success": true,
    "verdict": "Spam / Suspicious",
    "risk_level": "High",
    "risk_score": 69.1,
    "model_confidence": {
      "available": true,
      "spam_probability": 0.8886,
      "interpretation": "88.9% likelihood of being spam/scam pattern"
    },
    "warning_signs": [
      {
        "id": "credentials_otp",
        "title": "Credential & OTP Solicitation",
        "severity": "high",
        "description": "Requests secret authentication data...",
        "triggers": ["otp"]
      }
    ],
    "explanation": "The machine-learning classification model identified language patterns strongly characteristic of spam...",
    "recommendations": [
      "NEVER share OTPs, PINs, passwords, or CVVs..."
    ]
  }
  ```

---

## 8. Ethical & Security Notice
ScamShield does not store raw user text or sensitive identifiers permanently on servers. While the machine-learning pipeline achieves high accuracy (98.74%), no automated security filter is 100% impenetrable. A message that does not trigger flags must never be assumed automatically safe; users must always exercise independent verification.
