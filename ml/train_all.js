/**
 * CyberINTEL-AI — Node.js Model Trainer
 * Trains XSS, Phishing, and Anomaly models using @tensorflow/tfjs
 * and saves TF.js-format model files to models/
 *
 * Run: node ml/train_all.js
 */

'use strict';
const tf  = require('@tensorflow/tfjs');
const fs  = require('fs');
const path = require('path');

// ── Helpers ──────────────────────────────────────────────────

async function saveModel(model, outDir, scalerParams, extraJson) {
  fs.mkdirSync(outDir, { recursive: true });

  await model.save(
    tf.io.withSaveHandler(async (artifacts) => {
      const modelJSON = {
        format: 'layers-model',
        generatedBy: 'CyberINTEL-AI tfjs-trainer v1.0',
        convertedBy: null,
        modelTopology: artifacts.modelTopology,
        weightsManifest: [{
          paths: ['group1-shard1of1.bin'],
          weights: artifacts.weightSpecs,
        }],
      };
      fs.writeFileSync(path.join(outDir, 'model.json'),
                       JSON.stringify(modelJSON, null, 2));
      fs.writeFileSync(path.join(outDir, 'group1-shard1of1.bin'),
                       Buffer.from(artifacts.weightData));
      return { modelArtifactsInfo: { dateSaved: new Date(), modelTopologyType: 'JSON' } };
    })
  );

  if (scalerParams) {
    fs.writeFileSync(path.join(outDir, 'scaler.json'),
                     JSON.stringify(scalerParams, null, 2));
  }
  if (extraJson) {
    for (const [name, data] of Object.entries(extraJson)) {
      fs.writeFileSync(path.join(outDir, name), JSON.stringify(data, null, 2));
    }
  }
  console.log(`  [✓] Saved to ${outDir}/`);
}

// StandardScaler — matches sklearn behavior
function fitStandardScaler(data) {
  const n = data.length;
  const dim = data[0].length;
  const mean = new Array(dim).fill(0);
  const std  = new Array(dim).fill(0);

  for (const row of data) for (let j = 0; j < dim; j++) mean[j] += row[j] / n;
  for (const row of data) for (let j = 0; j < dim; j++) std[j] += (row[j] - mean[j]) ** 2 / n;
  for (let j = 0; j < dim; j++) std[j] = Math.sqrt(std[j]) || 1;

  return { mean, std, type: 'standard' };
}

function applyStandardScaler(data, scaler) {
  return data.map(row => row.map((v, j) => (v - scaler.mean[j]) / scaler.std[j]));
}

// MinMaxScaler — matches sklearn behavior
function fitMinMaxScaler(data) {
  const dim = data[0].length;
  const min = new Array(dim).fill(Infinity);
  const max = new Array(dim).fill(-Infinity);
  for (const row of data) {
    for (let j = 0; j < dim; j++) {
      if (row[j] < min[j]) min[j] = row[j];
      if (row[j] > max[j]) max[j] = row[j];
    }
  }
  const scale = min.map((mn, j) => (max[j] - mn) || 1);
  return { min, max, scale, type: 'minmax' };
}

function applyMinMaxScaler(data, scaler) {
  return data.map(row =>
    row.map((v, j) => Math.min(1, Math.max(0, (v - scaler.min[j]) / scaler.scale[j])))
  );
}

function toTensors(X, y) {
  return [tf.tensor2d(X, [X.length, X[0].length]), tf.tensor1d(y, 'float32')];
}

// ══════════════════════════════════════════════════════════════
//  1. XSS MODEL  (20-dim features → sigmoid)
// ══════════════════════════════════════════════════════════════

function extractXSSFeatures(text) {
  const t = String(text).toLowerCase();
  return [
    /<script/i.test(t) ? 1 : 0,
    /javascript:/i.test(t) ? 1 : 0,
    /on\w+=/i.test(t) ? 1 : 0,
    /eval\s*\(/.test(t) ? 1 : 0,
    t.includes('document.cookie') ? 1 : 0,
    t.includes('innerhtml') ? 1 : 0,
    t.includes('%3c') ? 1 : 0,
    /&#x?\d+;/i.test(t) ? 1 : 0,
    (t.match(/</g)  || []).length,
    (t.match(/>/g)  || []).length,
    (t.match(/"/g)  || []).length,
    (t.match(/'/g)  || []).length,
    t.length > 1000 ? 1 : 0,
    (t.match(/\\/g) || []).length,
    t.includes('fromcharcode') ? 1 : 0,
    t.includes('unescape') ? 1 : 0,
    /src\s*=/i.test(t) ? 1 : 0,
    /href\s*=\s*["']?\s*javascript/i.test(t) ? 1 : 0,
    /data:\s*text\/html/i.test(t) ? 1 : 0,
    t.length / 1000.0,
  ];
}

function buildXSSDataset() {
  const benign = [
    "Hello World",
    "document.getElementById('myDiv').innerText = 'safe text';",
    "const x = 5; console.log(x);",
    "var name = prompt('Enter name');",
    "window.location.href = '/dashboard';",
    "fetch('/api/data').then(r => r.json());",
    "document.querySelector('form').addEventListener('submit', handler);",
    "const el = document.createElement('div');",
    "let users = response.data.users;",
    "img.src = '/images/logo.png';",
    "console.log('Page loaded');",
    "return encodeURIComponent(param);",
  ];
  const malicious = [
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
    "<body onload=document.cookie>",
    "fromCharCode(97,108,101,114,116,40,49,41)",
  ];

  const X = [], y = [];
  const REP = 120;
  for (let i = 0; i < REP; i++) {
    for (const s of benign)    { X.push(extractXSSFeatures(s)); y.push(0); }
    for (const s of malicious) { X.push(extractXSSFeatures(s)); y.push(1); }
  }
  return { X, y };
}

function buildXSSModel() {
  const model = tf.sequential();
  model.add(tf.layers.dense({ inputShape: [20], units: 64, activation: 'relu',
                               kernelRegularizer: tf.regularizers.l2({ l2: 0.001 }) }));
  model.add(tf.layers.batchNormalization());
  model.add(tf.layers.dropout({ rate: 0.3 }));
  model.add(tf.layers.dense({ units: 32, activation: 'relu' }));
  model.add(tf.layers.dropout({ rate: 0.2 }));
  model.add(tf.layers.dense({ units: 16, activation: 'relu' }));
  model.add(tf.layers.dense({ units: 1,  activation: 'sigmoid' }));
  model.compile({ optimizer: tf.train.adam(0.001), loss: 'binaryCrossentropy',
                  metrics: ['accuracy'] });
  return model;
}

async function trainXSS() {
  console.log('\n' + '='.repeat(55));
  console.log('  XSS Detection Model');
  console.log('='.repeat(55));

  const { X, y } = buildXSSDataset();
  const scaler   = fitStandardScaler(X);
  const Xs       = applyStandardScaler(X, scaler);

  const model = buildXSSModel();
  const [Xt, yt] = toTensors(Xs, y);

  await model.fit(Xt, yt, {
    epochs: 60,
    batchSize: 64,
    validationSplit: 0.15,
    callbacks: {
      onEpochEnd: (epoch, logs) => {
        if ((epoch + 1) % 20 === 0) {
          console.log(`  Epoch ${epoch + 1}/60 — loss: ${logs.loss.toFixed(4)}, acc: ${logs.acc.toFixed(4)}`);
        }
      }
    },
    verbose: 0,
  });

  // Quick eval
  const pred = model.predict(Xt);
  const predArr = await pred.data();
  const correct = predArr.reduce((n, p, i) => n + (Math.round(p) === y[i] ? 1 : 0), 0);
  console.log(`  Train accuracy: ${(correct / y.length * 100).toFixed(1)}%`);

  tf.dispose([Xt, yt, pred]);
  await saveModel(model, 'models/xss', scaler);
  model.dispose();
}

// ══════════════════════════════════════════════════════════════
//  2. PHISHING MODEL  (30-dim URL features → sigmoid)
// ══════════════════════════════════════════════════════════════

const SUSPICIOUS_WORDS = new Set([
  'secure','account','webscr','login','ebayisapi','signin',
  'banking','confirm','logon','update','verify','support',
  'paypal','amazon','google','apple','microsoft','chase',
  'bank','wells','fargo','password','credential',
]);
const SHORT_SVCS = new Set([
  'bit.ly','tinyurl.com','goo.gl','t.co','ow.ly',
  'tiny.cc','is.gd','buff.ly','adf.ly','bit.do',
]);

function extractPhishingFeatures(url) {
  try {
    const full   = url.startsWith('http') ? url : `https://${url}`;
    const parsed = new URL(full);
    const domain = parsed.hostname.toLowerCase();
    const pathLo = parsed.pathname.toLowerCase();
    const urlLo  = full.toLowerCase();

    return [
      full.length,
      domain.length,
      pathLo.length,
      (full.match(/\./g)  || []).length,
      (full.match(/\//g)  || []).length,
      (full.match(/\?/g)  || []).length,
      (full.match(/=/g)   || []).length,
      (full.match(/@/g)   || []).length,
      (full.match(/&/g)   || []).length,
      (full.match(/#/g)   || []).length,
      (full.match(/%/g)   || []).length,
      (full.match(/-/g)   || []).length,
      (full.match(/_/g)   || []).length,
      full.startsWith('https') ? 1 : 0,
      full.includes('@') ? 1 : 0,
      full.slice(7).includes('//') ? 1 : 0,
      domain.startsWith('www.') ? 1 : 0,
      /\d+\.\d+\.\d+\.\d+/.test(domain) ? 1 : 0,
      SHORT_SVCS.has(domain) ? 1 : 0,
      [...SUSPICIOUS_WORDS].some(w => urlLo.includes(w)) ? 1 : 0,
      Math.max(0, (domain.match(/\./g) || []).length - 1),
      [...full].filter(c => /\d/.test(c)).length / Math.max(full.length, 1),
      /-{2,}/.test(domain) ? 1 : 0,
      (domain.match(/\d/g) || []).length > 3 ? 1 : 0,
      domain.length > 30 ? 1 : 0,
      pathLo.includes('login')   ? 1 : 0,
      pathLo.includes('verify')  ? 1 : 0,
      pathLo.includes('secure')  ? 1 : 0,
      pathLo.includes('account') ? 1 : 0,
      (pathLo.match(/\//g) || []).length > 5 ? 1 : 0,
    ];
  } catch {
    return new Array(30).fill(0);
  }
}

function buildPhishingDataset() {
  const legit = [
    "https://www.google.com/search?q=python",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://github.com/tensorflow/tensorflow",
    "https://www.wikipedia.org/wiki/Machine_learning",
    "https://stackoverflow.com/questions/tagged/python",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://news.ycombinator.com",
    "https://reddit.com/r/programming",
    "https://developer.mozilla.org/en-US/docs/Web",
    "https://www.cloudflare.com/learning/security/",
  ];
  const phish = [
    "http://amazon-security-alert.tk/login/verify",
    "http://paypal.secure-login.xyz/account/confirm",
    "http://192.168.1.1/google/signin/account.php",
    "http://g00gle.com-secure.tk/accounts/verify",
    "http://bit.ly/secure-banking-login",
    "http://microsoft-support-center.xyz/login@user",
    "http://apple.id.verification-required.tk",
    "http://secure--banking--login.tk/account",
    "http://paypal-verify-account.com/secure/login",
    "http://amazon.customer-security-alert.com/verify",
  ];

  const X = [], y = [];
  const REP = 150;
  for (let i = 0; i < REP; i++) {
    for (const u of legit)  { X.push(extractPhishingFeatures(u)); y.push(0); }
    for (const u of phish)  { X.push(extractPhishingFeatures(u)); y.push(1); }
  }
  return { X, y };
}

function buildPhishingModel() {
  const model = tf.sequential();
  model.add(tf.layers.dense({ inputShape: [30], units: 128, activation: 'relu' }));
  model.add(tf.layers.batchNormalization());
  model.add(tf.layers.dropout({ rate: 0.3 }));
  model.add(tf.layers.dense({ units: 64, activation: 'relu' }));
  model.add(tf.layers.dropout({ rate: 0.2 }));
  model.add(tf.layers.dense({ units: 32, activation: 'relu' }));
  model.add(tf.layers.dense({ units: 1,  activation: 'sigmoid' }));
  model.compile({ optimizer: 'adam', loss: 'binaryCrossentropy', metrics: ['accuracy'] });
  return model;
}

async function trainPhishing() {
  console.log('\n' + '='.repeat(55));
  console.log('  Phishing Detection Model');
  console.log('='.repeat(55));

  const { X, y } = buildPhishingDataset();
  const scaler   = fitStandardScaler(X);
  const Xs       = applyStandardScaler(X, scaler);

  const model = buildPhishingModel();
  const [Xt, yt] = toTensors(Xs, y);

  await model.fit(Xt, yt, {
    epochs: 60,
    batchSize: 128,
    validationSplit: 0.15,
    callbacks: {
      onEpochEnd: (epoch, logs) => {
        if ((epoch + 1) % 20 === 0) {
          console.log(`  Epoch ${epoch + 1}/60 — loss: ${logs.loss.toFixed(4)}, acc: ${logs.acc.toFixed(4)}`);
        }
      }
    },
    verbose: 0,
  });

  const pred = model.predict(Xt);
  const predArr = await pred.data();
  const correct = predArr.reduce((n, p, i) => n + (Math.round(p) === y[i] ? 1 : 0), 0);
  console.log(`  Train accuracy: ${(correct / y.length * 100).toFixed(1)}%`);

  tf.dispose([Xt, yt, pred]);
  await saveModel(model, 'models/phishing', scaler);
  model.dispose();
}

// ══════════════════════════════════════════════════════════════
//  3. ANOMALY AUTOENCODER  (21-dim → reconstruct → MSE threshold)
// ══════════════════════════════════════════════════════════════

function generateBenignFeatures(n = 4000) {
  const out = [];
  for (let i = 0; i < n; i++) {
    const nScripts  = Math.floor(Math.random() * 18) + 2;
    const nExt      = Math.floor(Math.random() * Math.min(nScripts, 9)) + 1;
    const nInline   = nScripts - nExt;
    const nIframes  = Math.floor(Math.random() * 3);
    const nForms    = Math.floor(Math.random() * 4);
    const nLinks    = Math.floor(Math.random() * 95) + 5;
    out.push([
      nScripts, nExt, nInline,
      nExt / Math.max(nScripts, 1),
      nIframes, 0,
      Math.floor(Math.random() * 2), 0,
      nForms, 0,
      Math.floor(Math.random() * 2),
      nLinks,
      Math.floor(Math.random() * 2),
      Math.floor(Math.random() * 29) + 1,
      nScripts + nIframes + nForms,
      nScripts > 20 ? 1 : 0,
      nExt > 10 ? 1 : 0,
      0, 1,
      Math.random() * 4.9 + 0.1,
      Math.random() * 2.9 + 0.1,
    ]);
  }
  return out;
}

function generateMaliciousFeatures(n = 400) {
  const out = [];
  for (let i = 0; i < n; i++) {
    const nScripts = Math.floor(Math.random() * 35) + 15;
    const nExt     = Math.floor(Math.random() * 30) + 10;
    const nInline  = Math.floor(Math.random() * 12) + 3;
    const nIframes = Math.floor(Math.random() * 7) + 3;
    const hidden   = Math.floor(Math.random() * 4) + 1;
    out.push([
      nScripts, nExt, nInline,
      Math.random() * 0.3 + 0.7,
      nIframes, hidden,
      Math.floor(Math.random() * 6) + 2, 1,
      Math.floor(Math.random() * 3),
      Math.floor(Math.random() * 2) + 1,
      Math.floor(Math.random() * 2),
      Math.floor(Math.random() * 20),
      Math.floor(Math.random() * 8) + 3,
      Math.floor(Math.random() * 45) + 5,
      Math.floor(Math.random() * 50) + 20,
      1, 1, 1, 0,
      Math.random() * 0.49 + 0.01,
      Math.random() * 1.9 + 0.1,
    ]);
  }
  return out;
}

function buildAutoencoder() {
  const input   = tf.input({ shape: [21] });
  let x = tf.layers.dense({ units: 16, activation: 'relu' }).apply(input);
  x = tf.layers.batchNormalization().apply(x);
  x = tf.layers.dense({ units: 8,  activation: 'relu' }).apply(x);
  const bottleneck = tf.layers.dense({ units: 4, activation: 'relu', name: 'bottleneck' }).apply(x);
  x = tf.layers.dense({ units: 8,  activation: 'relu' }).apply(bottleneck);
  x = tf.layers.dense({ units: 16, activation: 'relu' }).apply(x);
  const output = tf.layers.dense({ units: 21, activation: 'sigmoid', name: 'reconstruction' }).apply(x);

  const autoencoder = tf.model({ inputs: input, outputs: output });
  autoencoder.compile({ optimizer: tf.train.adam(0.001), loss: 'meanSquaredError' });
  return autoencoder;
}

async function trainAnomaly() {
  console.log('\n' + '='.repeat(55));
  console.log('  Anomaly Detection Autoencoder');
  console.log('='.repeat(55));

  const benign    = generateBenignFeatures(4000);
  const malicious = generateMaliciousFeatures(400);

  // MinMax scale using benign data only
  const scaler = fitMinMaxScaler(benign);
  const benignS = applyMinMaxScaler(benign, scaler);
  const malS    = applyMinMaxScaler(malicious, scaler);

  const autoencoder = buildAutoencoder();
  const Xt = tf.tensor2d(benignS);

  await autoencoder.fit(Xt, Xt, {
    epochs: 80,
    batchSize: 64,
    validationSplit: 0.1,
    callbacks: {
      onEpochEnd: (epoch, logs) => {
        if ((epoch + 1) % 20 === 0) {
          console.log(`  Epoch ${epoch + 1}/80 — loss: ${logs.loss.toFixed(6)}`);
        }
      }
    },
    verbose: 0,
  });

  // Compute reconstruction errors and calibrate threshold
  const benignPred = autoencoder.predict(Xt);
  const benignErr  = tf.mean(tf.square(tf.sub(Xt, benignPred)), 1);
  const benignErrArr = Array.from(await benignErr.data());

  const XtMal = tf.tensor2d(malS);
  const malPred = autoencoder.predict(XtMal);
  const malErr  = tf.mean(tf.square(tf.sub(XtMal, malPred)), 1);
  const malErrArr = Array.from(await malErr.data());

  // 95th percentile of benign errors as threshold
  benignErrArr.sort((a, b) => a - b);
  const threshold = benignErrArr[Math.floor(benignErrArr.length * 0.95)];

  const malDetected = malErrArr.filter(e => e > threshold).length;
  const recall = malDetected / malErrArr.length;
  const fp = benignErrArr.filter(e => e > threshold).length;
  const fpr = fp / benignErrArr.length;

  console.log(`  Threshold (95th pctile benign): ${threshold.toFixed(6)}`);
  console.log(`  Malicious recall: ${(recall * 100).toFixed(1)}%`);
  console.log(`  False positive rate: ${(fpr * 100).toFixed(1)}%`);

  tf.dispose([Xt, benignPred, benignErr, XtMal, malPred, malErr]);

  const thresholdData = {
    threshold,
    percentile: 95,
    recall,
    false_positive_rate: fpr,
    feature_dim: 21,
  };

  await saveModel(autoencoder, 'models/anomaly', scaler, {
    'threshold.json': thresholdData,
  });
  autoencoder.dispose();
}

// ── Main ─────────────────────────────────────────────────────

(async () => {
  console.log('CyberINTEL-AI Model Trainer');
  console.log('Using TF.js backend:', tf.getBackend());
  await tf.setBackend('cpu');
  await tf.ready();
  console.log('Backend ready:', tf.getBackend());

  try {
    await trainXSS();
    await trainPhishing();
    await trainAnomaly();

    console.log('\n' + '='.repeat(55));
    console.log('  All models trained and saved!');
    console.log('  models/xss/       — XSS detection');
    console.log('  models/phishing/  — Phishing detection');
    console.log('  models/anomaly/   — Anomaly autoencoder');
    console.log('  Run: npm run build');
    console.log('='.repeat(55));
  } catch (err) {
    console.error('Training failed:', err);
    process.exit(1);
  }
})();
