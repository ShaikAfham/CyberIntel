// ============================================================
// CyberINTEL-AI — ML Inference Engine
// Loads TF.js models from extension bundle and runs on-device
// inference for XSS, Phishing, and Anomaly detection.
// ============================================================

import * as tf from '@tensorflow/tfjs';
import { MLPrediction, DOMScanResult } from '../types/index';

// ── Types ────────────────────────────────────────────────────

interface StandardScaler { type: 'standard'; mean: number[]; std: number[]; }
interface MinMaxScaler   { type: 'minmax';   min:  number[]; max: number[]; scale: number[]; }
type Scaler = StandardScaler | MinMaxScaler;

// ── State ────────────────────────────────────────────────────

let xssModel:      tf.LayersModel | null = null;
let phishingModel: tf.LayersModel | null = null;
let anomalyModel:  tf.LayersModel | null = null;
let xssScaler:     Scaler | null = null;
let phishingScaler:Scaler | null = null;
let anomalyScaler: Scaler | null = null;
let anomalyThreshold = 0.056741;
let _modelsReady = false;

// ── Scaler Application ───────────────────────────────────────

function applyScaler(features: number[], scaler: Scaler): number[] {
  if (scaler.type === 'standard') {
    return features.map((v, i) => (v - scaler.mean[i]) / (scaler.std[i] || 1));
  }
  return features.map((v, i) =>
    Math.min(1, Math.max(0, (v - scaler.min[i]) / (scaler.scale[i] || 1)))
  );
}

// ── JSON Loader ───────────────────────────────────────────────

async function loadJSON<T>(extensionPath: string): Promise<T> {
  const url  = chrome.runtime.getURL(extensionPath);
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`Failed to load ${extensionPath}: ${resp.status}`);
  return resp.json() as Promise<T>;
}

// ── Model Loader ──────────────────────────────────────────────

function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms)
    ),
  ]);
}

export async function loadAllModels(): Promise<{ loaded: string[]; failed: string[] }> {
  let backendReady = false;

  // CPU backend only — WASM creates blob Workers which are blocked by MV3 CSP
  try {
    await withTimeout(
      (async () => { await tf.setBackend('cpu'); await tf.ready(); })(),
      3000, 'CPU backend'
    );
    backendReady = true;
    console.log('[CyberINTEL-AI/ML] CPU backend ready');
  } catch (e) {
    console.error('[CyberINTEL-AI/ML] No backend available:', (e as Error).message);
  }

  const loaded: string[] = [];
  const failed: string[] = [];

  if (!backendReady) {
    _modelsReady = false;
    return { loaded: [], failed: ['xss', 'phishing', 'anomaly'] };
  }

  const tryLoad = async (
    name: string,
    modelPath: string,
    scalerPath: string,
    setter: (m: tf.LayersModel, s: Scaler) => void
  ) => {
    try {
      const model  = await withTimeout(
        tf.loadLayersModel(chrome.runtime.getURL(modelPath)),
        8000, `${name} model`
      );
      const scaler = await withTimeout(loadJSON<Scaler>(scalerPath), 4000, `${name} scaler`);
      setter(model, scaler);
      const dim = (model.inputs[0].shape[1] as number);
      const warmup = tf.zeros([1, dim]);
      (model.predict(warmup) as tf.Tensor).dispose();
      warmup.dispose();
      loaded.push(name);
      console.log(`[CyberINTEL-AI/ML] ${name} loaded (${tf.getBackend()})`);
    } catch (err) {
      console.error(`[CyberINTEL-AI/ML] ${name} failed:`, err);
      failed.push(name);
    }
  };

  await tryLoad('xss', 'models/xss/model.json', 'models/xss/scaler.json',
    (m, s) => { xssModel = m; xssScaler = s; });

  await tryLoad('phishing', 'models/phishing/model.json', 'models/phishing/scaler.json',
    (m, s) => { phishingModel = m; phishingScaler = s; });

  try {
    const model  = await withTimeout(
      tf.loadLayersModel(chrome.runtime.getURL('models/anomaly/model.json')),
      8000, 'anomaly model'
    );
    const scaler = await withTimeout(loadJSON<Scaler>('models/anomaly/scaler.json'), 4000, 'anomaly scaler');
    const thr    = await withTimeout(loadJSON<{ threshold: number }>('models/anomaly/threshold.json'), 4000, 'anomaly threshold');
    anomalyModel     = model;
    anomalyScaler    = scaler;
    anomalyThreshold = thr.threshold;
    const warmup = tf.zeros([1, 21]);
    (model.predict(warmup) as tf.Tensor).dispose();
    warmup.dispose();
    loaded.push('anomaly');
    console.log(`[CyberINTEL-AI/ML] anomaly loaded (${tf.getBackend()})`);
  } catch (err) {
    console.error('[CyberINTEL-AI/ML] anomaly failed:', err);
    failed.push('anomaly');
  }

  _modelsReady = loaded.length > 0;
  return { loaded, failed };
}

export function getModelStatus() {
  return {
    xss:      xssModel !== null,
    phishing: phishingModel !== null,
    anomaly:  anomalyModel !== null,
    any: _modelsReady,
    all: xssModel !== null && phishingModel !== null && anomalyModel !== null,
  };
}

// ══════════════════════════════════════════════════════════════
//  XSS DETECTION  — 20-dim text feature vector
// ══════════════════════════════════════════════════════════════

function extractXSSFeatures(text: string): number[] {
  const t = text.toLowerCase();
  return [
    /<script/i.test(t) ? 1 : 0,
    /javascript:/i.test(t) ? 1 : 0,
    /on\w+\s*=/i.test(t) ? 1 : 0,         // matches train_real.js: /on\w+\s*=/i
    /eval\s*\(/.test(t) ? 1 : 0,
    t.includes('document.cookie') ? 1 : 0,
    t.includes('innerhtml') ? 1 : 0,
    t.includes('%3c') ? 1 : 0,
    /&#x?[0-9a-f]+;/i.test(t) ? 1 : 0,   // matches train_real.js: /&#x?[0-9a-f]+;/i
    Math.min((t.match(/</g)  || []).length, 20),
    Math.min((t.match(/>/g)  || []).length, 20),
    Math.min((t.match(/"/g)  || []).length, 20),
    Math.min((t.match(/'/g)  || []).length, 20),
    t.length > 1000 ? 1 : 0,
    Math.min((t.match(/\\/g) || []).length, 10),
    t.includes('fromcharcode') ? 1 : 0,
    t.includes('unescape') ? 1 : 0,
    /src\s*=/i.test(t) ? 1 : 0,
    /href\s*=\s*["']?\s*javascript/i.test(t) ? 1 : 0,
    /data:\s*text\/html/i.test(t) ? 1 : 0,
    Math.min(t.length / 1000.0, 5),        // capped at 5 like training
  ];
}

export async function runXSSPrediction(texts: string[]): Promise<MLPrediction | null> {
  if (!xssModel || !xssScaler || texts.length === 0) return null;

  const t0 = performance.now();

  // Extract features for each text and take the max confidence
  const featureSets = texts.map(t => applyScaler(extractXSSFeatures(t), xssScaler!));
  const batchTensor = tf.tensor2d(featureSets);
  const predTensor  = xssModel.predict(batchTensor) as tf.Tensor;
  const preds       = Array.from(await predTensor.data());
  tf.dispose([batchTensor, predTensor]);

  const maxConf  = Math.max(...preds);
  const isMal    = maxConf > 0.5;
  const worstIdx = preds.indexOf(maxConf);
  const rawFeatures = extractXSSFeatures(texts[worstIdx] || '');

  return {
    modelName: 'xss',
    label: isMal ? 'malicious' : 'benign',
    // Confidence = certainty in the classification (not raw malicious prob)
    confidence: isMal ? maxConf : 1 - maxConf,
    isMalicious: isMal,
    features: {
      script_tag: rawFeatures[0],
      js_protocol: rawFeatures[1],
      event_handler: rawFeatures[2],
      eval_call: rawFeatures[3],
      cookie_access: rawFeatures[4],
      innerHTML: rawFeatures[5],
    },
    inferenceTimeMs: performance.now() - t0,
  };
}

// ══════════════════════════════════════════════════════════════
//  PHISHING DETECTION  — 30-dim URL feature vector
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

function extractPhishingFeatures(url: string): number[] {
  try {
    const full   = url.startsWith('http') ? url : `https://${url}`;
    const parsed = new URL(full);
    const domain = parsed.hostname.toLowerCase();
    const pathLo = parsed.pathname.toLowerCase();
    const urlLo  = full.toLowerCase();

    return [
      Math.min(full.length, 500),
      Math.min(domain.length, 100),
      Math.min(pathLo.length, 200),
      Math.min((full.match(/\./g)  || []).length, 20),
      Math.min((full.match(/\//g)  || []).length, 20),
      Math.min((full.match(/\?/g)  || []).length, 10),
      Math.min((full.match(/=/g)   || []).length, 20),
      Math.min((full.match(/@/g)   || []).length, 5),
      Math.min((full.match(/&/g)   || []).length, 20),
      Math.min((full.match(/#/g)   || []).length, 5),
      Math.min((full.match(/%/g)   || []).length, 30),
      Math.min((full.match(/-/g)   || []).length, 20),
      Math.min((full.match(/_/g)   || []).length, 15),
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

export async function runPhishingPrediction(url: string): Promise<MLPrediction | null> {
  if (!phishingModel || !phishingScaler) return null;

  const t0       = performance.now();
  const raw      = extractPhishingFeatures(url);
  const scaled   = applyScaler(raw, phishingScaler);
  const tensor   = tf.tensor2d([scaled]);
  const predOut  = phishingModel.predict(tensor) as tf.Tensor;
  const [conf]   = Array.from(await predOut.data());
  tf.dispose([tensor, predOut]);

  const isMal = conf > 0.5;
  return {
    modelName: 'phishing',
    label: isMal ? 'phishing' : 'legitimate',
    confidence: isMal ? conf : 1 - conf,
    isMalicious: isMal,
    features: {
      url_length: raw[0],
      has_https: raw[13],
      has_ip_address: raw[17],
      is_short_url: raw[18],
      suspicious_word: raw[19],
      subdomain_depth: raw[20],
    },
    inferenceTimeMs: performance.now() - t0,
  };
}

// ══════════════════════════════════════════════════════════════
//  ANOMALY DETECTION  — 21-dim DOM feature → autoencoder MSE
// ══════════════════════════════════════════════════════════════

function extractAnomalyFeatures(dom: DOMScanResult): number[] {
  const scripts  = dom.scripts;
  const iframes  = dom.iframes;
  const forms    = dom.forms;
  const links    = dom.links;

  const extScripts    = scripts.filter(s => s.isExternal);
  const inlineScripts = scripts.filter(s => s.isInline);
  const hiddenIframes = iframes.filter(i => i.isHidden);
  const tpIframes     = iframes.filter(i => i.isThirdParty);

  const nScripts = scripts.length;
  const nExt     = extScripts.length;

  return [
    nScripts,
    nExt,
    inlineScripts.length,
    nExt / Math.max(nScripts, 1),
    iframes.length,
    hiddenIframes.length,
    tpIframes.length,
    hiddenIframes.length > 0 ? 1 : 0,
    forms.length,
    forms.filter(f => f.submitsOverHTTP).length,
    forms.filter(f => f.hasPasswordField).length,
    links.length,
    links.filter(l => l.isSuspicious).length,
    links.filter(l => l.isExternal).length,
    nScripts + iframes.length + forms.length,
    nScripts > 20 ? 1 : 0,
    nExt > 10 ? 1 : 0,
    iframes.length > 5 ? 1 : 0,
    1, // isHTTPS placeholder (updated by caller)
    1.0, // normalized page size (unknown at inference time)
    1.0, // normalized DOM depth (unknown at inference time)
  ];
}

export async function runAnomalyPrediction(dom: DOMScanResult): Promise<MLPrediction | null> {
  if (!anomalyModel || !anomalyScaler) return null;

  const t0      = performance.now();
  const raw     = extractAnomalyFeatures(dom);
  const scaled  = applyScaler(raw, anomalyScaler);
  const tensor  = tf.tensor2d([scaled]);
  const recon   = anomalyModel.predict(tensor) as tf.Tensor;
  const inputT  = tf.tensor2d([scaled]);
  const mse     = tf.mean(tf.square(tf.sub(inputT, recon))).dataSync()[0];
  tf.dispose([tensor, recon, inputT]);

  // 1.2× safety buffer for feature 19/20 mismatch (content/resource ratios fixed at 1.0 in inference)
  const adjustedThreshold = anomalyThreshold * 1.2;
  const isMal = mse > adjustedThreshold;
  const confidence = isMal
    ? Math.min(0.95, (mse - adjustedThreshold) / adjustedThreshold)
    : Math.min(0.95, 1 - mse / adjustedThreshold);

  return {
    modelName: 'anomaly',
    label: isMal ? 'anomalous' : 'normal',
    confidence,
    isMalicious: isMal,
    features: {
      total_scripts:    raw[0],
      external_scripts: raw[1],
      hidden_iframes:   raw[5],
      suspicious_links: raw[12],
      mse_score:        mse,
      threshold:        anomalyThreshold,
    },
    inferenceTimeMs: performance.now() - t0,
  };
}

// ══════════════════════════════════════════════════════════════
//  FULL PIPELINE — runs all available models
// ══════════════════════════════════════════════════════════════

export async function runAllInference(
  url: string,
  dom: DOMScanResult
): Promise<MLPrediction[]> {
  if (!_modelsReady) return [];

  const results: MLPrediction[] = [];

  // Gather texts for XSS: inline script snippets + input payloads
  const xssTexts: string[] = [
    ...dom.scripts.filter(s => s.isInline && s.snippet).map(s => s.snippet!),
    ...dom.inputs.filter(i => i.hasXSSPayload && i.payload).map(i => i.payload!),
    // URL params
    (() => {
      try { return new URL(url).search; } catch { return ''; }
    })(),
  ].filter(Boolean);

  try {
    const xss = await runXSSPrediction(xssTexts.length ? xssTexts : ['']);
    if (xss) results.push(xss);
  } catch (e) {
    console.warn('[ML] XSS inference failed:', e);
  }

  try {
    const phish = await runPhishingPrediction(url);
    if (phish) results.push(phish);
  } catch (e) {
    console.warn('[ML] Phishing inference failed:', e);
  }

  try {
    const anomaly = await runAnomalyPrediction(dom);
    if (anomaly) results.push(anomaly);
  } catch (e) {
    console.warn('[ML] Anomaly inference failed:', e);
  }

  return results;
}
