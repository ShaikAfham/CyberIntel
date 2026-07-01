"""
CyberINTEL-AI — Phishing Detection Model Training
====================================================
Trains an XGBoost classifier to detect phishing websites
from URL structure and domain features.

Datasets:
  - Kaggle: kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning
  - Mendeley: data.mendeley.com/datasets/kvpkc4j658

Run:
  pip install pandas xgboost scikit-learn tensorflow tensorflowjs numpy whois tldextract
  python train_phishing.py

Output:
  phishing_model_tfjs/ — TensorFlow.js model files

Current State:
  If phishing_dataset.csv is absent, a small synthetic dataset (~40 samples) is
  generated so the pipeline can be exercised end-to-end.  The resulting model is
  a DEMO BASELINE with limited real-world accuracy.

Retraining on Real Data:
  1. kaggle datasets download shashwatwork/phishing-dataset-for-machine-learning
     (or the Mendeley mirror listed above)
  2. Place as  ml/phishing/phishing_dataset.csv  (expected columns: url, label).
  3. python train_phishing.py
  4. The script auto-detects the CSV (~11 000 samples) and trains on real URLs.
  5. Copy phishing_model_tfjs/ → extension/models/phishing/  and rebuild.
"""

import os
import re
import json
import pickle
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, f1_score, roc_auc_score, classification_report
)
from sklearn.preprocessing import StandardScaler
import xgboost as xgb
import tensorflow as tf
from tensorflow import keras
import tensorflowjs as tfjs

# ─── Config ───────────────────────────────────────────────
DATASET_PATH  = "phishing_dataset.csv"
MODEL_OUT_DIR = "phishing_model_tfjs"
RANDOM_STATE  = 42

# ─── URL Feature Extractor ────────────────────────────────
class URLFeatureExtractor:
    """
    Extracts 30 features from a URL for phishing detection.
    Covers URL structure, domain characteristics, and suspicious patterns.
    
    These features are aligned with research achieving 98%+ accuracy:
    - "Phishing Website Detection Using Machine Learning" papers
    - The Kaggle dataset uses 48 features; we implement the most predictive ones.
    """
    
    SUSPICIOUS_WORDS = {
        'secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin',
        'banking', 'confirm', 'blog', 'logon', 'update', 'verify',
        'support', 'paypal', 'amazon', 'google', 'apple', 'microsoft',
        'chase', 'bank', 'wells', 'fargo', 'password', 'credential',
    }
    
    SHORT_URL_SERVICES = {
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
        'tiny.cc', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do',
    }
    
    def extract(self, url: str) -> list:
        """Extract all features for a given URL."""
        try:
            parsed = urlparse(url if url.startswith('http') else f'https://{url}')
            domain = parsed.netloc.lower()
            path   = parsed.path.lower()
            
            return [
                # URL length features
                len(url),
                len(domain),
                len(path),
                
                # Special character counts
                url.count('.'),
                url.count('/'),
                url.count('?'),
                url.count('='),
                url.count('@'),
                url.count('&'),
                url.count('#'),
                url.count('%'),
                url.count('-'),
                url.count('_'),
                
                # Binary flags
                1 if url.startswith('https') else 0,
                1 if '@' in url else 0,              # @ in URL = suspicious
                1 if '//' in url[7:] else 0,         # Double slash after protocol
                1 if domain.startswith('www.') else 0,
                1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0,  # IP address
                1 if domain in self.SHORT_URL_SERVICES else 0,
                1 if any(w in url.lower() for w in self.SUSPICIOUS_WORDS) else 0,
                
                # Subdomain depth (dots in domain minus TLD dots)
                max(0, domain.count('.') - 1),
                
                # Digit ratio
                sum(c.isdigit() for c in url) / max(len(url), 1),
                
                # Domain-specific
                1 if re.search(r'-{2,}', domain) else 0,  # Multiple hyphens
                1 if len(re.findall(r'\d', domain)) > 3 else 0,  # Many digits in domain
                1 if len(domain) > 30 else 0,            # Very long domain
                
                # Path features
                1 if 'login' in path else 0,
                1 if 'verify' in path else 0,
                1 if 'secure' in path else 0,
                1 if 'account' in path else 0,
                1 if path.count('/') > 5 else 0,        # Deep path
            ]
        except Exception:
            return [0] * 30  # Return zeros on parse failure
    
    @property
    def feature_names(self) -> list:
        return [
            'url_length', 'domain_length', 'path_length',
            'dot_count', 'slash_count', 'query_count',
            'equals_count', 'at_count', 'ampersand_count',
            'hash_count', 'percent_count', 'hyphen_count', 'underscore_count',
            'has_https', 'has_at_in_url', 'has_double_slash',
            'starts_with_www', 'has_ip_address', 'is_short_url',
            'has_suspicious_word', 'subdomain_depth',
            'digit_ratio', 'has_multiple_hyphens',
            'has_many_digits', 'very_long_domain',
            'login_in_path', 'verify_in_path', 'secure_in_path',
            'account_in_path', 'deep_path',
        ]


def load_dataset():
    """
    Load phishing dataset.
    Expected CSV: 'url' column + 'label' column (1=phishing, 0=legitimate)
    The Kaggle dataset has 48 pre-computed features — use those directly if available.
    """
    extractor = URLFeatureExtractor()
    
    if os.path.exists(DATASET_PATH):
        print("[*] Loading dataset from file...")
        df = pd.read_csv(DATASET_PATH)
        
        if 'url' in df.columns:
            print("[*] Extracting URL features...")
            X = np.array([extractor.extract(u) for u in df['url']])
            y = df['label'].values if 'label' in df.columns else df['status'].map({'phishing': 1, 'legitimate': 0}).values
        else:
            # Pre-computed feature dataset (48 features)
            feature_cols = [c for c in df.columns if c not in ['url', 'label', 'status', 'index']]
            X = df[feature_cols].values.astype(float)
            y = df['label'].values if 'label' in df.columns else df['Result'].values
    else:
        print("[!] Dataset not found. Creating synthetic demo dataset...")
        X, y = create_demo_dataset(extractor)
    
    print(f"[*] Dataset: {X.shape[0]} samples, {X.shape[1]} features")
    print(f"[*] Phishing: {y.sum()} | Legitimate: {len(y)-y.sum()}")
    return X, y


def create_demo_dataset(extractor: URLFeatureExtractor):
    """Synthetic demo data — replace with real dataset."""
    legitimate_urls = [
        "https://www.google.com/search?q=python",
        "https://www.amazon.com/dp/B08N5WRWNW",
        "https://github.com/tensorflow/tensorflow",
        "https://www.wikipedia.org/wiki/Machine_learning",
        "https://stackoverflow.com/questions/tagged/python",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://news.ycombinator.com",
        "https://reddit.com/r/programming",
    ] * 150

    phishing_urls = [
        "http://amazon-security-alert.tk/login/verify",
        "http://paypal.secure-login.xyz/account/confirm",
        "http://192.168.1.1/google/signin/account.php",
        "http://g00gle.com-secure.tk/accounts/verify",
        "http://bit.ly/secure-banking-login",
        "http://microsoft-support-center.xyz/login@user",
        "http://apple.id.verification-required.tk",
        "http://secure--banking--login.tk/account",
    ] * 150

    all_urls = legitimate_urls + phishing_urls
    X = np.array([extractor.extract(u) for u in all_urls])
    y = np.array([0] * len(legitimate_urls) + [1] * len(phishing_urls))
    return X, y


def train_xgboost(X_train, y_train, X_test, y_test):
    """XGBoost — best performance on tabular URL features."""
    print("\n[*] Training XGBoost classifier...")
    
    scale_pos_weight = (y_train == 0).sum() / (y_train == 1).sum()
    
    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight,
        random_state=RANDOM_STATE,
        use_label_encoder=False,
        eval_metric='logloss',
        early_stopping_rounds=20,
        verbosity=1,
    )
    
    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=50,
    )
    
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    
    print(f"\n[✓] XGBoost Results:")
    print(f"  Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"  F1 Score:  {f1_score(y_test, y_pred):.4f}")
    print(f"  ROC-AUC:   {roc_auc_score(y_test, y_prob):.4f}")
    print(f"\n{classification_report(y_test, y_pred)}")
    
    return model


def build_keras_phishing_model(input_dim: int) -> keras.Model:
    """Neural network version for TF.js conversion."""
    model = keras.Sequential([
        keras.layers.InputLayer(shape=(input_dim,)),
        keras.layers.Dense(128, activation='relu'),
        keras.layers.BatchNormalization(),
        keras.layers.Dropout(0.3),
        keras.layers.Dense(64, activation='relu'),
        keras.layers.Dropout(0.2),
        keras.layers.Dense(32, activation='relu'),
        keras.layers.Dense(1, activation='sigmoid'),
    ])
    
    model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy', keras.metrics.AUC()],
    )
    return model


def main():
    print("=" * 60)
    print("  CyberINTEL-AI — Phishing Detection Model Training")
    print("=" * 60)
    
    X, y = load_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )
    
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)
    
    with open('phishing_scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    
    # Train XGBoost
    xgb_model = train_xgboost(X_train, y_train, X_test, y_test)
    
    # Train Keras for TF.js export
    print("\n[*] Training Keras model for TF.js conversion...")
    keras_model = build_keras_phishing_model(X_train_s.shape[1])
    
    keras_model.fit(
        X_train_s, y_train,
        validation_data=(X_test_s, y_test),
        epochs=50,
        batch_size=128,
        callbacks=[keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True)],
        verbose=1,
    )
    
    keras_model.save('phishing_keras_model.h5')
    
    print(f"\n[*] Exporting to TF.js → {MODEL_OUT_DIR}/")
    os.makedirs(MODEL_OUT_DIR, exist_ok=True)
    tfjs.converters.save_keras_model(keras_model, MODEL_OUT_DIR)
    
    print("\n[✓] Done! Copy phishing_model_tfjs/ → extension/models/phishing/")


if __name__ == '__main__':
    main()
