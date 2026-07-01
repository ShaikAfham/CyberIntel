"""
CyberINTEL-AI — Anomaly Detection Model Training (Autoencoder)
=================================================================
Trains an Autoencoder on BENIGN website features to learn what
"normal" pages look like. Any page that deviates significantly
is flagged as an anomaly — SOC-style unsupervised detection.

This detects:
  - Unusual script loading patterns
  - Hidden iframes
  - Obfuscated code
  - Abnormal DOM structures
  - Cryptojacking-style resource usage

Run:
  pip install tensorflow tensorflowjs pandas numpy scikit-learn
  python train_anomaly.py

Output:
  anomaly_model_tfjs/  — TF.js Autoencoder model
  anomaly_threshold.json — Reconstruction error threshold

Current State:
  Training data is fully synthetic — normal page features are procedurally generated
  from realistic distributions; malicious samples are similarly generated.  The
  autoencoder learns a valid reconstruction manifold but the threshold is tuned on
  synthetic data, so real-world detection rates will vary.

Retraining on Real Data:
  1. Download the CICIDS-2017 or CICIDS-2018 benign traffic feature CSVs from
     cicresearch.ca/CIC-IDS-2017  (use the "Monday-WorkingHours.pcap_ISCX.csv" for
     benign-only samples, or filter Label == 'BENIGN').
  2. Map / prune columns to match the 20-feature vector expected by this script
     (see generate_normal_features() for the feature list).
  3. Place as  ml/anomaly/benign_features.csv  and set DATASET_PATH at the top.
  4. python train_anomaly.py
  5. Copy anomaly_model_tfjs/ and anomaly_threshold.json → extension/models/anomaly/.
"""

import os
import json
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score
import tensorflow as tf
from tensorflow import keras
import tensorflowjs as tfjs

# ─── Config ───────────────────────────────────────────────
MODEL_OUT_DIR        = "anomaly_model_tfjs"
ANOMALY_THRESHOLD_PC = 95    # Flag top 5% reconstruction errors as anomalies
RANDOM_STATE         = 42

# ─── Feature Vector for DOM/Page Analysis ─────────────────
def extract_page_features(page_data: dict) -> list:
    """
    Convert DOM scan data into a numerical feature vector.
    This function must mirror what the extension sends for inference.
    
    Input: DOMScanResult + metadata from scanner.ts
    """
    scripts     = page_data.get('scripts', [])
    iframes     = page_data.get('iframes', [])
    forms       = page_data.get('forms', [])
    links       = page_data.get('links', [])
    
    external_scripts = [s for s in scripts if s.get('isExternal', False)]
    inline_scripts   = [s for s in scripts if s.get('isInline', False)]
    hidden_iframes   = [i for i in iframes if i.get('isHidden', False)]
    third_party_frames = [i for i in iframes if i.get('isThirdParty', False)]
    
    features = [
        # Script features
        len(scripts),
        len(external_scripts),
        len(inline_scripts),
        len(external_scripts) / max(len(scripts), 1),  # External ratio
        
        # Iframe features
        len(iframes),
        len(hidden_iframes),
        len(third_party_frames),
        1 if len(hidden_iframes) > 0 else 0,
        
        # Form features
        len(forms),
        sum(1 for f in forms if f.get('submitsOverHTTP', False)),
        sum(1 for f in forms if f.get('hasPasswordField', False)),
        
        # Link features
        len(links),
        sum(1 for l in links if l.get('isSuspicious', False)),
        sum(1 for l in links if l.get('isExternal', False)),
        
        # Complexity indicators
        len(scripts) + len(iframes) + len(forms),  # Resource count
        1 if len(scripts) > 20 else 0,             # Many scripts
        1 if len(external_scripts) > 10 else 0,   # Many external scripts
        1 if len(iframes) > 5 else 0,              # Many iframes
        
        # Page metadata
        page_data.get('isHTTPS', 0),
        min(page_data.get('pageSize', 0) / 100000, 10),  # Normalized page size
        min(page_data.get('domDepth', 0) / 50, 10),      # Normalized DOM depth
    ]
    
    return features

FEATURE_DIM = 21  # Must match len(features) above


# ─── Generate Synthetic Benign Training Data ──────────────
def generate_benign_data(n_samples: int = 5000) -> np.ndarray:
    """
    Generate synthetic 'normal' page features for training the autoencoder.
    
    In production: replace this with real data collected by visiting
    Alexa/Tranco top 10K legitimate websites and recording their features.
    
    Run a scraper or use the extension's monitor data to collect real features.
    """
    rng = np.random.RandomState(RANDOM_STATE)
    
    samples = []
    for _ in range(n_samples):
        # Typical legitimate page characteristics
        n_scripts    = rng.randint(2, 20)
        n_external   = rng.randint(1, min(n_scripts, 10))
        n_inline     = n_scripts - n_external
        n_iframes    = rng.randint(0, 3)
        n_forms      = rng.randint(0, 4)
        n_links      = rng.randint(5, 100)
        is_https     = 1  # Legitimate sites almost always use HTTPS
        
        sample = [
            n_scripts,
            n_external,
            n_inline,
            n_external / max(n_scripts, 1),
            n_iframes,
            0,           # No hidden iframes in benign
            rng.randint(0, 2),
            0,           # No hidden iframes
            n_forms,
            0,           # No HTTP form submissions
            rng.randint(0, 2),
            n_links,
            rng.randint(0, 2),
            rng.randint(1, 30),
            n_scripts + n_iframes + n_forms,
            1 if n_scripts > 20 else 0,
            1 if n_external > 10 else 0,
            0,
            is_https,
            rng.uniform(0.1, 5),   # Normalized page size
            rng.uniform(0.1, 3),   # Normalized DOM depth
        ]
        samples.append(sample)
    
    return np.array(samples, dtype=np.float32)


def generate_malicious_data(n_samples: int = 500) -> np.ndarray:
    """
    Generate synthetic malicious page features for threshold calibration.
    NOT used in training — only for evaluating the threshold.
    """
    rng = np.random.RandomState(RANDOM_STATE + 1)
    
    samples = []
    for _ in range(n_samples):
        sample = [
            rng.randint(15, 50),   # Many scripts
            rng.randint(10, 40),   # Many external
            rng.randint(3, 15),    # Many inline
            rng.uniform(0.7, 1.0), # High external ratio
            rng.randint(3, 10),    # Many iframes
            rng.randint(1, 5),     # Hidden iframes
            rng.randint(2, 8),     # Third party iframes
            1,                     # Has hidden iframes
            rng.randint(0, 3),
            rng.randint(1, 3),     # HTTP form submissions
            rng.randint(0, 2),
            rng.randint(0, 20),
            rng.randint(3, 10),    # Suspicious links
            rng.randint(5, 50),
            rng.randint(20, 70),
            1,
            1,
            1,                     # Many iframes flag
            0,                     # Often HTTP
            rng.uniform(0.01, 0.5),
            rng.uniform(0.1, 2),
        ]
        samples.append(sample)
    
    return np.array(samples, dtype=np.float32)


# ─── Autoencoder Architecture ─────────────────────────────
def build_autoencoder(input_dim: int) -> tuple:
    """
    Autoencoder: learns to compress and reconstruct BENIGN pages.
    Malicious pages have high reconstruction error → flagged as anomalies.
    
    Architecture:
      Encoder: input → 16 → 8 → 4 (bottleneck)
      Decoder: 4 → 8 → 16 → input
    """
    input_layer = keras.layers.Input(shape=(input_dim,))
    
    # Encoder
    encoded = keras.layers.Dense(16, activation='relu')(input_layer)
    encoded = keras.layers.BatchNormalization()(encoded)
    encoded = keras.layers.Dense(8, activation='relu')(encoded)
    encoded = keras.layers.Dense(4, activation='relu', name='bottleneck')(encoded)
    
    # Decoder
    decoded = keras.layers.Dense(8, activation='relu')(encoded)
    decoded = keras.layers.Dense(16, activation='relu')(decoded)
    decoded = keras.layers.Dense(input_dim, activation='sigmoid', name='reconstruction')(decoded)
    
    autoencoder = keras.Model(input_layer, decoded, name='autoencoder')
    encoder     = keras.Model(input_layer, encoded, name='encoder')
    
    autoencoder.compile(
        optimizer=keras.optimizers.Adam(0.001),
        loss='mse',
    )
    
    return autoencoder, encoder


def calculate_reconstruction_errors(model, X: np.ndarray) -> np.ndarray:
    """Calculate Mean Squared Error reconstruction error per sample."""
    X_pred = model.predict(X, verbose=0)
    errors = np.mean(np.power(X - X_pred, 2), axis=1)
    return errors


def calibrate_threshold(autoencoder, X_benign, X_malicious) -> dict:
    """
    Set the anomaly threshold at the 95th percentile of benign reconstruction errors.
    This means 5% false positive rate on benign data.
    """
    benign_errors   = calculate_reconstruction_errors(autoencoder, X_benign)
    malicious_errors = calculate_reconstruction_errors(autoencoder, X_malicious)
    
    threshold = np.percentile(benign_errors, ANOMALY_THRESHOLD_PC)
    
    # Evaluate detection performance
    benign_labels   = np.zeros(len(X_benign))
    malicious_labels = np.ones(len(X_malicious))
    
    all_errors = np.concatenate([benign_errors, malicious_errors])
    all_labels = np.concatenate([benign_labels, malicious_labels])
    
    predictions = (all_errors > threshold).astype(int)
    
    tp = np.sum((predictions == 1) & (all_labels == 1))
    fp = np.sum((predictions == 1) & (all_labels == 0))
    tn = np.sum((predictions == 0) & (all_labels == 0))
    fn = np.sum((predictions == 0) & (all_labels == 1))
    
    precision  = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall     = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1         = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    auc        = roc_auc_score(all_labels, all_errors)
    
    print(f"\n[*] Anomaly Detection Results (threshold={threshold:.6f}):")
    print(f"  Precision (malicious correctly flagged): {precision:.4f}")
    print(f"  Recall (malicious detected):             {recall:.4f}")
    print(f"  F1 Score:                                {f1:.4f}")
    print(f"  ROC-AUC:                                 {auc:.4f}")
    print(f"  False Positive Rate:                     {fp / len(X_benign):.4f}")
    
    print(f"\n  Benign error  — mean: {benign_errors.mean():.6f}, 95th pctile: {np.percentile(benign_errors, 95):.6f}")
    print(f"  Malicious error — mean: {malicious_errors.mean():.6f}, 95th pctile: {np.percentile(malicious_errors, 95):.6f}")
    
    return {
        'threshold':         float(threshold),
        'precision':         float(precision),
        'recall':            float(recall),
        'f1':                float(f1),
        'roc_auc':           float(auc),
        'false_positive_rate': float(fp / len(X_benign)),
        'percentile':        ANOMALY_THRESHOLD_PC,
        'feature_dim':       int(X_benign.shape[1]),
    }


def main():
    print("=" * 60)
    print("  CyberINTEL-AI — Anomaly Detection Model Training")
    print("=" * 60)
    
    # 1. Generate / load data
    print("\n[*] Generating benign training data...")
    X_benign   = generate_benign_data(5000)
    X_malicious = generate_malicious_data(500)
    
    print(f"[*] Benign samples:    {len(X_benign)}")
    print(f"[*] Malicious samples: {len(X_malicious)} (threshold calibration only)")
    
    # 2. Normalize features to [0, 1]
    scaler = MinMaxScaler()
    X_benign_scaled   = scaler.fit_transform(X_benign).astype(np.float32)
    X_malicious_scaled = scaler.transform(X_malicious).astype(np.float32)
    
    import pickle
    with open('anomaly_scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    
    # 3. Train autoencoder on BENIGN data only
    X_train, X_val = train_test_split(X_benign_scaled, test_size=0.1, random_state=RANDOM_STATE)
    
    print(f"\n[*] Building autoencoder (input_dim={FEATURE_DIM})...")
    autoencoder, encoder = build_autoencoder(FEATURE_DIM)
    autoencoder.summary()
    
    print("\n[*] Training on benign data only...")
    history = autoencoder.fit(
        X_train, X_train,           # Input = Target for autoencoder
        validation_data=(X_val, X_val),
        epochs=100,
        batch_size=64,
        callbacks=[
            keras.callbacks.EarlyStopping(patience=10, restore_best_weights=True),
            keras.callbacks.ReduceLROnPlateau(factor=0.5, patience=5),
        ],
        verbose=1,
    )
    
    # 4. Calibrate threshold
    threshold_data = calibrate_threshold(autoencoder, X_benign_scaled, X_malicious_scaled)
    
    # 5. Save threshold
    with open('anomaly_threshold.json', 'w') as f:
        json.dump(threshold_data, f, indent=2)
    print(f"\n[✓] Threshold saved to anomaly_threshold.json")
    
    # 6. Export to TF.js
    print(f"\n[*] Exporting to TF.js → {MODEL_OUT_DIR}/")
    os.makedirs(MODEL_OUT_DIR, exist_ok=True)
    tfjs.converters.save_keras_model(autoencoder, MODEL_OUT_DIR)
    
    # Also save the scaler params as JSON for JavaScript use
    scaler_params = {
        'data_min':   scaler.data_min_.tolist(),
        'data_max':   scaler.data_max_.tolist(),
        'scale':      scaler.scale_.tolist(),
        'feature_dim': FEATURE_DIM,
    }
    with open(os.path.join(MODEL_OUT_DIR, 'scaler.json'), 'w') as f:
        json.dump(scaler_params, f, indent=2)
    
    print("\n" + "="*60)
    print("  Training Complete!")
    print(f"  Threshold: {threshold_data['threshold']:.6f}")
    print(f"  Copy '{MODEL_OUT_DIR}/' → extension/models/anomaly/")
    print(f"  Copy 'anomaly_threshold.json' → extension/models/anomaly/")
    print("="*60)


if __name__ == '__main__':
    main()
