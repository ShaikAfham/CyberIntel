"""
CyberINTEL-AI — XSS Detection Model Training
================================================
Trains a Random Forest classifier to detect XSS payloads in
JavaScript snippets, URL parameters, and form inputs.

Dataset: Kaggle XSS Dataset
  kaggle.com/datasets/syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning

Run:
  pip install pandas scikit-learn tensorflowjs numpy
  python train_xss.py

Output:
  xss_model.h5          — Keras model (for reference)
  xss_model_tfjs/       — TensorFlow.js model files (load in browser)
  xss_vectorizer.pkl    — TF-IDF vectorizer

Current State:
  If xss_dataset.csv is absent, a small synthetic dataset (~50 samples) is generated
  automatically so the pipeline can be exercised end-to-end.  The resulting model is
  a DEMO BASELINE — accuracy on real traffic will be low.

Retraining on Real Data:
  1. kaggle datasets download syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning
  2. Unzip and place as  ml/xss/xss_dataset.csv  (two columns: Sentence, Label).
  3. python train_xss.py
  4. The script auto-detects the CSV and trains on ~15 000 real samples.
  5. Copy xss_model_tfjs/ → extension/models/xss/  and rebuild the extension.
"""

import os
import re
import json
import pickle
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report, confusion_matrix
)
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow import keras
import tensorflowjs as tfjs

# ─── Config ───────────────────────────────────────────────
DATASET_PATH  = "xss_dataset.csv"    # Download from Kaggle
MODEL_OUT_DIR = "xss_model_tfjs"
RANDOM_STATE  = 42
TEST_SIZE     = 0.2

# ─── Feature Extraction ───────────────────────────────────
def extract_features(text: str) -> list:
    """
    Extract 20 hand-crafted features from text (script/URL/input content).
    These features are designed to capture XSS attack patterns.
    Must match the JavaScript extractXSSFeatures() function in the extension.
    """
    text = str(text).lower()
    
    features = [
        # Pattern-based binary features
        1 if re.search(r'<script', text, re.I) else 0,
        1 if re.search(r'javascript:', text, re.I) else 0,
        1 if re.search(r'on\w+=', text, re.I) else 0,          # onerror=, onload=
        1 if re.search(r'eval\s*\(', text, re.I) else 0,
        1 if 'document.cookie' in text else 0,
        1 if 'innerhtml' in text else 0,
        1 if '%3c' in text else 0,                               # URL-encoded <
        1 if re.search(r'&#x?\d+;', text, re.I) else 0,        # HTML entities
        
        # Count-based numeric features
        len(re.findall(r'<', text)),
        len(re.findall(r'>', text)),
        len(re.findall(r'"', text)),
        len(re.findall(r"'", text)),
        1 if len(text) > 1000 else 0,                           # Long payloads
        len(re.findall(r'\\', text)),
        
        # Advanced patterns
        1 if 'fromcharcode' in text else 0,
        1 if 'unescape' in text else 0,
        1 if re.search(r'src\s*=', text, re.I) else 0,
        1 if re.search(r'href\s*=\s*["\']?\s*javascript', text, re.I) else 0,
        1 if re.search(r'data:\s*text/html', text, re.I) else 0,
        len(text) / 1000.0,                                     # Normalized length
    ]
    
    return features


def load_and_prepare_data():
    """
    Load the Kaggle XSS dataset and prepare feature matrix.
    Expected CSV format: two columns — 'Sentence' (text) and 'Label' (0/1)
    """
    print("[*] Loading dataset...")
    
    if not os.path.exists(DATASET_PATH):
        # Create a small synthetic dataset for testing the pipeline
        print("[!] Dataset not found. Creating synthetic demo dataset...")
        demo_data = create_demo_dataset()
        df = pd.DataFrame(demo_data)
    else:
        df = pd.read_csv(DATASET_PATH)
    
    print(f"[*] Dataset shape: {df.shape}")
    print(f"[*] Label distribution:\n{df['Label'].value_counts()}")
    
    # Extract features
    print("[*] Extracting features...")
    X = np.array([extract_features(text) for text in df['Sentence']])
    y = df['Label'].values
    
    print(f"[*] Feature matrix shape: {X.shape}")
    return X, y


def create_demo_dataset():
    """
    Minimal synthetic dataset to test the pipeline without real data.
    Replace this with the real Kaggle dataset for actual training.
    """
    benign = [
        "Hello World",
        "document.getElementById('myDiv').innerText = 'safe text';",
        "const x = 5; console.log(x);",
        "var name = prompt('Enter name');",
        "window.location.href = '/dashboard';",
        "fetch('/api/data').then(r => r.json());",
        "document.querySelector('form').addEventListener('submit', handler);",
        "const el = document.createElement('div');",
    ] * 100
    
    malicious = [
        "<script>alert('XSS')</script>",
        "javascript:alert(document.cookie)",
        "<img src=x onerror=alert(1)>",
        "';alert('xss');//",
        "eval(atob('YWxlcnQoMSk='))",
        "<iframe src=javascript:alert(1)>",
        "document.write('<script>evil()</scr'+'ipt>')",
        "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "<svg onload=alert(1)>",
    ] * 100
    
    return {
        'Sentence': benign + malicious,
        'Label':    [0] * len(benign) + [1] * len(malicious),
    }


def train_random_forest(X_train, y_train):
    """Train a Random Forest classifier — fast, accurate, interpretable."""
    print("[*] Training Random Forest...")
    
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        class_weight='balanced',
    )
    clf.fit(X_train, y_train)
    return clf


def build_keras_model(input_dim: int) -> keras.Model:
    """
    Build a small neural network on top of the feature vector.
    This can be converted to TensorFlow.js for browser inference.
    """
    model = keras.Sequential([
        keras.layers.InputLayer(shape=(input_dim,)),
        keras.layers.Dense(64, activation='relu',
                           kernel_regularizer=keras.regularizers.l2(0.001)),
        keras.layers.BatchNormalization(),
        keras.layers.Dropout(0.3),
        keras.layers.Dense(32, activation='relu'),
        keras.layers.Dropout(0.2),
        keras.layers.Dense(16, activation='relu'),
        keras.layers.Dense(1, activation='sigmoid'),   # Binary: benign/malicious
    ])
    
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss='binary_crossentropy',
        metrics=['accuracy', keras.metrics.AUC(name='auc')],
    )
    
    return model


def evaluate_model(model, X_test, y_test, model_name: str):
    """Print comprehensive evaluation metrics."""
    print(f"\n{'='*50}")
    print(f"  {model_name} Evaluation")
    print(f"{'='*50}")
    
    if hasattr(model, 'predict_proba'):
        y_prob = model.predict_proba(X_test)[:, 1]
        y_pred = (y_prob >= 0.5).astype(int)
    else:
        y_prob = model.predict(X_test).ravel()
        y_pred = (y_prob >= 0.5).astype(int)
    
    print(f"Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"Recall:    {recall_score(y_test, y_pred):.4f}")
    print(f"F1 Score:  {f1_score(y_test, y_pred):.4f}")
    print(f"ROC-AUC:   {roc_auc_score(y_test, y_prob):.4f}")
    print(f"\nClassification Report:\n{classification_report(y_test, y_pred)}")
    print(f"\nConfusion Matrix:\n{confusion_matrix(y_test, y_pred)}")


def export_to_tfjs(keras_model, output_dir: str):
    """Convert Keras model to TensorFlow.js format for browser use."""
    print(f"\n[*] Exporting to TensorFlow.js format → {output_dir}")
    os.makedirs(output_dir, exist_ok=True)
    tfjs.converters.save_keras_model(keras_model, output_dir)
    print(f"[✓] TF.js model saved to {output_dir}/")
    print(f"    Files: model.json + group1-shard*.bin")
    print(f"    Copy to: extension/models/xss/")


def main():
    print("=" * 60)
    print("  CyberINTEL-AI — XSS Detection Model Training")
    print("=" * 60)
    
    # 1. Load data
    X, y = load_and_prepare_data()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"\n[*] Train: {X_train.shape[0]} samples | Test: {X_test.shape[0]} samples")
    
    # 2. Normalize features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled  = scaler.transform(X_test)
    
    # Save scaler for inference
    with open('xss_scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    print("[*] Scaler saved to xss_scaler.pkl")
    
    # 3. Train Random Forest (best for feature-based XSS detection)
    rf_model = train_random_forest(X_train, y_train)
    evaluate_model(rf_model, X_test, y_test, "Random Forest")
    
    # 4. Train Keras neural network (for TF.js conversion)
    print("\n[*] Training Keras Neural Network...")
    keras_model = build_keras_model(input_dim=X_train_scaled.shape[1])
    keras_model.summary()
    
    callbacks = [
        keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True),
        keras.callbacks.ReduceLROnPlateau(factor=0.5, patience=3),
    ]
    
    history = keras_model.fit(
        X_train_scaled, y_train,
        validation_data=(X_test_scaled, y_test),
        epochs=50,
        batch_size=64,
        callbacks=callbacks,
        verbose=1,
    )
    
    evaluate_model(keras_model, X_test_scaled, y_test, "Keras Neural Network")
    
    # 5. Save Keras model
    keras_model.save('xss_keras_model.h5')
    print("[✓] Keras model saved to xss_keras_model.h5")
    
    # 6. Export to TF.js
    export_to_tfjs(keras_model, MODEL_OUT_DIR)
    
    print("\n" + "="*60)
    print("  Training Complete!")
    print("  Next steps:")
    print(f"  1. Copy '{MODEL_OUT_DIR}/' → extension/models/xss/")
    print("  2. Copy 'xss_scaler.pkl' → extension/models/xss/")
    print("  3. Run `npm run build` to bundle the extension")
    print("="*60)


if __name__ == '__main__':
    main()
