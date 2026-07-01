# ⬡ CyberINTEL-AI

**AI-Powered Browser Extension for Penetration Testing & SOC Analysis**

> Final Year Major Project — B.E. Computer Science & Engineering (AI & Data Science)

[![Chrome MV3](https://img.shields.io/badge/Chrome-Manifest%20V3-blue?logo=googlechrome)](https://developer.chrome.com/docs/extensions/mv3/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue?logo=typescript)](https://www.typescriptlang.org/)
[![TensorFlow.js](https://img.shields.io/badge/TensorFlow.js-4.x-orange?logo=tensorflow)](https://www.tensorflow.org/js)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## What Is It?

CyberINTEL-AI is a browser extension that performs **automated penetration testing** and **real-time SOC-style monitoring** on every website you visit — entirely on-device using on-device AI models.

Unlike SaaS scanners that require URL submission, CyberINTEL-AI has **full access to the DOM, cookies, network requests, and page behaviour** through Chrome's content scripts — giving it capabilities no web app can match.

---

## Features

### 🔍 Rule-Based Scans (Tier 1)
| Feature | What It Detects |
|---------|----------------|
| Security Headers | Missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
| SSL/TLS Analysis | HTTP vs HTTPS, certificate validity |
| Cookie Security | Missing HttpOnly, Secure, SameSite flags |
| Sensitive Files | `.env`, `.git/`, `phpinfo.php`, `backup.sql`, config files |
| Directory Listing | Exposed `/api/`, `/uploads/`, `/logs/` directories |
| Form Security | Login forms submitting over HTTP |
| Script Analysis | Suspicious third-party domains, ad injectors |
| Mixed Content | HTTP resources on HTTPS pages |

### 🤖 AI/ML Scans (Tier 2)
| Model | Algorithm | Detects | Target Accuracy |
|-------|-----------|---------|-----------------|
| XSS Detection | Random Forest + CNN | XSS payloads in scripts, URL params, inputs | >98% |
| Phishing Detection | XGBoost + Neural Net | Fake login pages, suspicious domains | >97% |
| Anomaly Detection | Autoencoder | Hidden iframes, obfuscated code, unusual patterns | High recall |

All models run **entirely on-device** via TensorFlow.js WASM backend. No data leaves your browser.

### 📡 SOC Monitoring (Tier 3)
- Real-time DOM mutation observer — detects script injections live
- `eval()` interception — flags obfuscated code execution
- Fetch/XHR monitoring — logs all network requests
- Form submission tracking — alerts on unencrypted credential submission
- `localStorage`/`sessionStorage` write monitoring

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Chrome Browser                                          │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Service Worker (background/service-worker.ts)  │    │
│  │  • Loads TF.js WASM models                      │    │
│  │  • Runs ML inference                            │    │
│  │  • Analyses HTTP headers + cookies              │    │
│  │  • Checks sensitive files                       │    │
│  │  • Stores results in chrome.storage             │    │
│  └──────────────┬──────────────────────────────────┘    │
│                 │ chrome.runtime.sendMessage             │
│  ┌──────────────┴──────────────────────────────────┐    │
│  │  Content Scripts (injected into every page)     │    │
│  │  scanner.ts  — DOM scan (forms, scripts, iframes│    │
│  │  monitor.ts  — Live SOC monitoring              │    │
│  └──────────────┬──────────────────────────────────┘    │
│                 │                                        │
│  ┌──────────────┴──────────────────────────────────┐    │
│  │  Popup UI (popup/popup.ts)                      │    │
│  │  • Security score ring (0-100, grade A-F)       │    │
│  │  • Vulnerability list by severity               │    │
│  │  • Live monitor event stream                    │    │
│  │  • PDF & JSON report export                     │    │
│  └─────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────┘

Optional: Flask Backend (backend/app.py)
  • WHOIS lookups, SSLLabs API, PhishTank API, CVE/NVD
  • Report storage and history
```

---

## Project Structure

```
cyberintel-ai/
├── manifest.json              Chrome MV3 manifest
├── package.json               Node dependencies
├── tsconfig.json              TypeScript config
├── webpack.config.js          Build configuration
│
├── src/
│   ├── types/index.ts         All shared TypeScript types
│   ├── background/
│   │   └── service-worker.ts  Background hub (ML + analysis)
│   ├── content/
│   │   ├── scanner.ts         DOM security scanner
│   │   └── monitor.ts         Real-time SOC monitor
│   ├── ml-inference/
│   │   └── index.ts           TF.js model loader + inference
│   ├── popup/
│   │   ├── popup.html         Dashboard UI
│   │   ├── popup.ts           UI controller
│   │   ├── popup.css          Dark terminal styles
│   │   └── settings.html      Settings page
│   └── utils/
│       ├── scoring.ts         Score + grade calculator
│       └── report.ts          PDF + JSON export
│
├── models/
│   ├── xss/model.json         XSS TF.js model (after training)
│   ├── phishing/model.json    Phishing TF.js model
│   └── anomaly/model.json     Anomaly autoencoder model
│
├── ml/
│   ├── xss/train_xss.py       XSS model training (Random Forest + Keras)
│   ├── phishing/train_phishing.py  Phishing model (XGBoost + Keras)
│   ├── anomaly/train_anomaly.py    Anomaly autoencoder training
│   └── requirements.txt       Python ML dependencies
│
├── backend/
│   ├── app.py                 Optional Flask backend
│   └── requirements.txt       Flask dependencies
│
└── generate_icons.py          Icon generator script
```

---

## Quick Start

### Step 1 — Install Node Dependencies

```bash
npm install
```

### Step 2 — Generate Icons

```bash
pip install Pillow
python generate_icons.py
```

### Step 3 — Build the Extension

```bash
# Development (watch mode — auto-rebuilds on save)
npm run dev

# Production build
npm run build
```

### Step 4 — Load in Chrome

1. Go to `chrome://extensions`
2. Enable **Developer Mode** (top right)
3. Click **Load unpacked**
4. Select the `dist/` folder

The extension icon appears in your toolbar. Click it to open the dashboard.

---

## Training the ML Models

> Run these in Google Colab (free GPU) or locally with Python 3.10+

### Setup

```bash
cd ml
pip install -r requirements.txt
```

### Model 1 — XSS Detection

```bash
# Download dataset first:
# kaggle.com/datasets/syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning
# Save as ml/xss/xss_dataset.csv

cd ml/xss
python train_xss.py

# Copy output to extension:
cp -r xss_model_tfjs/* ../../models/xss/
```

### Model 2 — Phishing Detection

```bash
# Download dataset:
# kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning
# Save as ml/phishing/phishing_dataset.csv

cd ml/phishing
python train_phishing.py

cp -r phishing_model_tfjs/* ../../models/phishing/
```

### Model 3 — Anomaly Detection

```bash
# No dataset needed — trains on synthetic benign data
# For best results: collect real benign page features first

cd ml/anomaly
python train_anomaly.py

cp -r anomaly_model_tfjs/* ../../models/anomaly/
cp anomaly_threshold.json ../../models/anomaly/threshold.json
```

After copying models, rebuild the extension:
```bash
npm run build
```

---

## Optional: Flask Backend

```bash
cd backend
pip install -r requirements.txt
python app.py
# Server runs at http://localhost:5000
```

Configure in the extension: **Settings → Backend URL → http://localhost:5000**

Backend provides:
- WHOIS domain lookups
- PhishTank URL verification
- SSLLabs API integration
- CVE/NVD database searches
- Server-side scan report storage

---

## Testing the Extension

Test against vulnerable applications running locally:

| App | Setup | What to Test |
|-----|-------|-------------|
| **DVWA** | `docker run -p 80:80 vulnerables/web-dvwa` | XSS, CSRF, SQLi |
| **OWASP WebGoat** | `docker run -p 8080:8080 webgoat/webgoat` | OWASP Top 10 |
| **OWASP Juice Shop** | `docker run -p 3000:3000 bkimminich/juice-shop` | Modern vulnerabilities |

---

## ML Model Performance Targets

| Model | Accuracy | F1 Score | Inference Time |
|-------|----------|----------|----------------|
| XSS Detection | >98% | >0.97 | <50ms |
| Phishing Detection | >97% | >0.97 | <50ms |
| Anomaly Detection | — | High Recall | <100ms |

---

## Datasets

| Dataset | URL | Size | Used For |
|---------|-----|------|----------|
| XSS Dataset | kaggle.com/datasets/syedsaqlainhussain | 200K+ samples | XSS model |
| Phishing Dataset | kaggle.com/datasets/shashwatwork | 10K URLs, 48 features | Phishing model |
| Mendeley Phishing | data.mendeley.com/datasets/kvpkc4j658 | 2M+ URLs | Phishing model (large) |
| PhishTank | phishtank.com | Live feed | Phishing verification |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Extension | TypeScript, Chrome Manifest V3 |
| ML (Browser) | TensorFlow.js 4.x, WASM backend |
| ML (Training) | Python, scikit-learn, Keras, XGBoost |
| PDF Reports | jsPDF + jspdf-autotable |
| Build | Webpack 5 |
| Backend (Optional) | Python Flask |

---

## Roadmap

- [x] Rule-based security scan (headers, SSL, cookies, sensitive files)
- [x] DOM scanner (forms, scripts, iframes, XSS patterns)
- [x] Real-time SOC monitoring (MutationObserver, fetch hooks)
- [x] ML inference engine (TF.js WASM)
- [x] PDF + JSON report generation
- [x] Settings page
- [x] Flask backend
- [ ] XSS model trained and integrated
- [ ] Phishing model trained and integrated
- [ ] Anomaly model trained and integrated
- [ ] Chrome Web Store submission
- [ ] Firefox MV3 port

---

## Academic References

- OWASP Top 10: owasp.org/www-project-top-ten
- XSS Detection with ML: "Cross-Site Scripting Attack Detection by Machine Learning" (JOIV 2023)
- Phishing Detection: "Phishing Website Detection Using XGBoost" (arXiv 2024)
- Chrome MV3: developer.chrome.com/docs/extensions/mv3/
- TensorFlow.js WASM: tensorflow.org/js/guide/platform_environment

---

## License

MIT License — see [LICENSE](LICENSE)

> **Ethical Use Only.** This tool is for authorized security testing, academic research, and defensive security analysis. Do not use against systems you do not own or have explicit written permission to test.
