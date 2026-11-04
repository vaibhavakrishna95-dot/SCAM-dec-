"""
SCAMSHIELD — Machine Learning Training Pipeline
Loads the UCI SMS Spam Collection dataset, cleans data, trains TF-IDF + Classifier models,
evaluates performance metrics, runs DBSCAN exploratory clustering, and saves the production pipeline.
"""

import os
import re
import json
import zipfile
import io
import requests
import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
from sklearn.decomposition import TruncatedSVD
from sklearn.cluster import DBSCAN

# Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

DATASET_FILE = os.path.join(DATA_DIR, "SMSSpamCollection")
MODEL_PATH = os.path.join(MODELS_DIR, "scam_model.joblib")
METRICS_PATH = os.path.join(MODELS_DIR, "model_metrics.json")
DBSCAN_SAMPLE_PATH = os.path.join(MODELS_DIR, "dbscan_sample.json")


def clean_text(text: str) -> str:
    """Preprocess text: lowercasing, standardizing URLs/phones/numbers, removing junk."""
    if not isinstance(text, str):
        return ""
    text = text.lower()
    # Normalize URLs
    text = re.sub(r'https?://\S+|www\.\S+', ' urladdr ', text)
    # Normalize email addresses
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', ' emailaddr ', text)
    # Normalize currency symbols and amounts
    text = re.sub(r'[$£€₹]\s*\d+([.,]\d+)?', ' moneynum ', text)
    # Normalize phone/digits patterns
    text = re.sub(r'\b\d{10,12}\b', ' phonenum ', text)
    text = re.sub(r'\b\d+\b', ' numbertoken ', text)
    # Remove excessive punctuation
    text = re.sub(r'[^\w\s]', ' ', text)
    # Normalize multiple whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def fetch_dataset() -> str:
    """Fetch the UCI SMS Spam Collection dataset if not already present."""
    if os.path.exists(DATASET_FILE) and os.path.getsize(DATASET_FILE) > 1000:
        print(f"[+] Dataset already present at: {DATASET_FILE}")
        return DATASET_FILE

    uci_url = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
    mirror_url = "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"

    print("[*] Downloading dataset...")
    try:
        r = requests.get(uci_url, timeout=15)
        if r.status_code == 200:
            with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                z.extract("SMSSpamCollection", path=DATA_DIR)
            print(f"[+] Extracted UCI dataset successfully to {DATASET_FILE}")
            return DATASET_FILE
    except Exception as e:
        print(f"[-] UCI direct download failed: {e}. Trying mirror...")

    try:
        r2 = requests.get(mirror_url, timeout=15)
        if r2.status_code == 200:
            with open(DATASET_FILE, "wb") as f:
                f.write(r2.content)
            print(f"[+] Downloaded dataset from mirror to {DATASET_FILE}")
            return DATASET_FILE
    except Exception as e:
        print(f"[-] Mirror download failed: {e}")

    raise RuntimeError("Failed to acquire dataset from online repositories.")


def load_and_preprocess_data(dataset_path: str):
    """Load, inspect, clean duplicates/nulls, and return cleaned DataFrame."""
    print("[*] Loading dataset...")
    # Dataset is tab-separated: label \t text
    df = pd.read_csv(
        dataset_path,
        sep='\t',
        header=None,
        names=['label', 'message'],
        encoding='utf-8',
        quoting=3
    )

    print(f"[*] Initial record count: {len(df)}")
    print(f"[*] Class distribution before deduplication:\n{df['label'].value_counts()}")

    # Drop nulls
    df = df.dropna(subset=['label', 'message'])

    # Deduplicate
    initial_len = len(df)
    df = df.drop_duplicates(subset=['message']).reset_index(drop=True)
    print(f"[*] Deduplicated records: {initial_len - len(df)} duplicates removed. Remaining: {len(df)}")
    print(f"[*] Class distribution after deduplication:\n{df['label'].value_counts()}")

    # Binary label: 1 for spam, 0 for ham
    df['target'] = df['label'].map({'ham': 0, 'spam': 1})
    df['clean_message'] = df['message'].apply(clean_text)

    # Filter out empty cleaned messages if any
    df = df[df['clean_message'].str.strip().str.len() > 0].reset_index(drop=True)
    return df


def train_and_evaluate(df: pd.DataFrame):
    """Train Naive Bayes and Logistic Regression, evaluate, select best, and save metrics."""
    X = df['clean_message']
    y = df['target']

    # Stratified train/test split (80/20) with fixed random seed
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"[*] Training samples: {len(X_train)} (Ham: {(y_train==0).sum()}, Spam: {(y_train==1).sum()})")
    print(f"[*] Testing samples:  {len(X_test)} (Ham: {(y_test==0).sum()}, Spam: {(y_test==1).sum()})")

    # Define TF-IDF Vectorizer
    vectorizer = TfidfVectorizer(
        max_features=6000,
        ngram_range=(1, 2),
        sublinear_tf=True,
        min_df=2
    )

    # 1. Multinomial Naive Bayes Pipeline
    nb_pipeline = Pipeline([
        ('tfidf', vectorizer),
        ('clf', MultinomialNB(alpha=0.1))
    ])

    # 2. Logistic Regression Pipeline
    lr_pipeline = Pipeline([
        ('tfidf', vectorizer),
        ('clf', LogisticRegression(C=5.0, max_iter=1000, random_state=42))
    ])

    print("[*] Training Multinomial Naive Bayes...")
    nb_pipeline.fit(X_train, y_train)
    nb_preds = nb_pipeline.predict(X_test)
    nb_probs = nb_pipeline.predict_proba(X_test)[:, 1]

    print("[*] Training Logistic Regression...")
    lr_pipeline.fit(X_train, y_train)
    lr_preds = lr_pipeline.predict(X_test)
    lr_probs = lr_pipeline.predict_proba(X_test)[:, 1]

    def compute_metrics(y_true, y_pred, y_prob):
        cm = confusion_matrix(y_true, y_pred).tolist()
        return {
            "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
            "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
            "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
            "confusion_matrix": {
                "tn": int(cm[0][0]),
                "fp": int(cm[0][1]),
                "fn": int(cm[1][0]),
                "tp": int(cm[1][1])
            }
        }

    nb_metrics = compute_metrics(y_test, nb_preds, nb_probs)
    lr_metrics = compute_metrics(y_test, lr_preds, lr_probs)

    print("\n--- Model Evaluation Results ---")
    print(f"Naive Bayes:        Acc: {nb_metrics['accuracy']:.4f} | Prec: {nb_metrics['precision']:.4f} | Rec: {nb_metrics['recall']:.4f} | F1: {nb_metrics['f1']:.4f}")
    print(f"Logistic Regression: Acc: {lr_metrics['accuracy']:.4f} | Prec: {lr_metrics['precision']:.4f} | Rec: {lr_metrics['recall']:.4f} | F1: {lr_metrics['f1']:.4f}")

    # Choose best model based on F1-score (or Logistic Regression for calibrated probabilities)
    # Logistic Regression with C=5.0 generally provides well-calibrated probabilities for risk scoring
    best_name = "Logistic Regression" if lr_metrics["f1"] >= nb_metrics["f1"] else "Multinomial Naive Bayes"
    best_pipeline = lr_pipeline if best_name == "Logistic Regression" else nb_pipeline

    print(f"\n[+] Selected Best Model for Production: {best_name}")

    # Save best pipeline
    joblib.dump(best_pipeline, MODEL_PATH)
    print(f"[+] Saved model pipeline to: {MODEL_PATH}")

    # Save metrics JSON
    metrics_data = {
        "dataset": {
            "total_records": int(len(df)),
            "ham_count": int((df['target'] == 0).sum()),
            "spam_count": int((df['target'] == 1).sum()),
            "train_samples": int(len(X_train)),
            "test_samples": int(len(X_test)),
            "source": "UCI SMS Spam Collection (Almeida & Hidalgo)"
        },
        "selected_model": best_name,
        "models": {
            "Multinomial Naive Bayes": nb_metrics,
            "Logistic Regression": lr_metrics
        }
    }

    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics_data, f, indent=2)
    print(f"[+] Saved metrics report to: {METRICS_PATH}")

    # Generate DBSCAN Exploratory Clustering Artifact
    generate_dbscan_artifact(df, vectorizer)


def generate_dbscan_artifact(df: pd.DataFrame, vectorizer: TfidfVectorizer):
    """
    Run DBSCAN clustering on a stratified sample of messages.
    Reduces TF-IDF vectors using TruncatedSVD to 2D for interactive visualization.
    Identifies core clusters and noise points (potential outliers / zero-day campaigns).
    """
    print("\n[*] Generating DBSCAN Exploratory Clustering sample...")
    # Sample 500 points (250 ham, 250 spam) for clear web visualization without browser lag
    ham_sample = df[df['target'] == 0].sample(n=min((df['target'] == 0).sum(), 250), random_state=42)
    spam_sample = df[df['target'] == 1].sample(n=min((df['target'] == 1).sum(), 250), random_state=42)
    sample_df = pd.concat([ham_sample, spam_sample]).sample(frac=1, random_state=42).reset_index(drop=True)

    tfidf_sample = vectorizer.transform(sample_df['clean_message'])

    # Reduce to 2D for 2D scatter plotting
    svd_2d = TruncatedSVD(n_components=2, random_state=42)
    coords_2d = svd_2d.fit_transform(tfidf_sample)

    # Also reduce to 20 components for DBSCAN cosine clustering
    svd_dense = TruncatedSVD(n_components=min(20, tfidf_sample.shape[1] - 1), random_state=42)
    reduced_features = svd_dense.fit_transform(tfidf_sample)

    # DBSCAN: cosine metric
    dbscan = DBSCAN(eps=0.40, min_samples=3, metric='cosine')
    cluster_labels = dbscan.fit_predict(reduced_features)

    n_clusters = len(set(cluster_labels)) - (1 if -1 in cluster_labels else 0)
    n_noise = int((cluster_labels == -1).sum())
    print(f"[+] DBSCAN completed: {n_clusters} clusters found, {n_noise} noise points identified.")

    points = []
    for i, row in sample_df.iterrows():
        points.append({
            "id": int(i),
            "x": round(float(coords_2d[i, 0]), 4),
            "y": round(float(coords_2d[i, 1]), 4),
            "cluster": int(cluster_labels[i]),
            "is_noise": bool(cluster_labels[i] == -1),
            "true_label": "spam" if int(row['target']) == 1 else "ham",
            "snippet": str(row['message'])[:90] + ("..." if len(str(row['message'])) > 90 else "")
        })

    dbscan_summary = {
        "n_samples": len(sample_df),
        "n_clusters": int(n_clusters),
        "n_noise": int(n_noise),
        "noise_ratio": round(float(n_noise / len(sample_df)), 4),
        "points": points
    }

    with open(DBSCAN_SAMPLE_PATH, "w", encoding="utf-8") as f:
        json.dump(dbscan_summary, f, indent=2)
    print(f"[+] Saved DBSCAN visualization sample to: {DBSCAN_SAMPLE_PATH}")


def main():
    print("==================================================")
    print("  SCAMSHIELD — Machine Learning Training Pipeline")
    print("==================================================")
    dataset_file = fetch_dataset()
    df = load_and_preprocess_data(dataset_file)
    train_and_evaluate(df)
    print("\n[SUCCESS] Training pipeline finished successfully!")


if __name__ == "__main__":
    main()
