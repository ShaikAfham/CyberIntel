// ============================================================
// CyberINTEL-AI — Background Service Worker
// Passive-only security analyzer. Orchestrates all scan
// checks. ML runs in offscreen document.
// ============================================================

import {
  ExtensionMessage, ScanResult, Vulnerability, Severity,
  ScanCategory, SecurityHeaders, HeaderAnalysis, SSLAnalysis,
  CookieAnalysis, DOMScanResult, MonitorEvent, DEFAULT_SETTINGS,
  MLPrediction,
} from '../types/index';

import {
  calculateSecurityScore, scoreToGrade,
  countBySeverity, generateVulnId,
} from '../utils/scoring';

// ─── Helpers ──────────────────────────────────────────────
const delay = (ms: number) => new Promise<void>(r => setTimeout(r, ms));
const activeScans = new Map<string, AbortController>();

interface ProgressData {
  addedFindings?: Vulnerability[];
  currentScore?: number;
  currentGrade?: string;
  currentCounts?: { critical: number; high: number; medium: number; low: number; info: number };
}

function broadcastProgress(
  scanId: string, stage: string, pct: number, msg: string,
  data?: ProgressData,
) {
  chrome.runtime.sendMessage({
    type: 'SCAN_PROGRESS',
    payload: { scanId, stage, pct, message: msg, ...(data ?? {}) },
  } as ExtensionMessage).catch(() => {});
}

// ─── Offscreen document (persistent ML host) ──────────────
const OFFSCREEN_URL = chrome.runtime.getURL('offscreen/offscreen.html');
let _offscreenGuard: Promise<void> | null = null;

async function ensureOffscreen(): Promise<void> {
  // Check if already open — getContexts available Chrome 116+
  try {
    const contexts = await (chrome.runtime as any).getContexts({
      contextTypes: ['OFFSCREEN_DOCUMENT'],
    });
    if (contexts.length > 0) return;
  } catch { /* older Chrome — fall through */ }

  if (_offscreenGuard) { await _offscreenGuard; return; }
  _offscreenGuard = (chrome as any).offscreen
    .createDocument({
      url: OFFSCREEN_URL,
      reasons: ['WORKERS'],
      justification: 'TF.js ML inference for CyberINTEL-AI security scanning',
    })
    .catch((e: Error) => {
      // Silently ignore "already exists" errors
      if (!e?.message?.includes('Only a single')) throw e;
    })
    .finally(() => { _offscreenGuard = null; });
  await _offscreenGuard;
}

// ─── Service-worker keepalive (prevents MV3 SW from dying) ─
function swKeepAlive(): () => void {
  const id = setInterval(() => {
    chrome.storage.session.set({ _ka: Date.now() }).catch(() => {});
  }, 20_000);
  return () => clearInterval(id);
}

// ─── DOM Extraction via existing content script ───────────
async function extractDOM(tabId: number): Promise<DOMScanResult | null> {
  try {
    const resp = await chrome.tabs.sendMessage(tabId, { type: 'SCAN_REQUEST' } as ExtensionMessage);
    return resp?.payload?.domResult ?? null;
  } catch { return null; }
}

// ─── Header Analysis ──────────────────────────────────────
function analyzeHeaders(headers: Record<string, string>): {
  analysis: SecurityHeaders; vulns: Vulnerability[];
} {
  const vulns: Vulnerability[] = [];
  let idx = 0;

  const check = (
    name: keyof SecurityHeaders,
    key: string,
    rec: string,
    sev: Severity,
    subCheckId: string,
  ): HeaderAnalysis => {
    const value   = headers[key.toLowerCase()] ?? null;
    const present = value !== null;
    if (!present) {
      vulns.push({
        id: generateVulnId('HDR', ++idx), title: `Missing ${key} header`,
        description: `The ${key} security header is absent.`,
        severity: sev, category: ScanCategory.HEADERS,
        evidence: `${key}: (not present)`, location: 'HTTP Response Headers',
        remediation: rec, detectedAt: Date.now(), detectedBy: 'rule',
        subCheckId, checkId: 'headers',
      });
    }
    return { present, value, secure: present, recommendation: rec };
  };

  const cspValue = headers['content-security-policy'] ?? null;

  const analysis: SecurityHeaders = {
    'Content-Security-Policy':   check('Content-Security-Policy',   'content-security-policy',   "Add: Content-Security-Policy: default-src 'self'",                   Severity.MEDIUM, 'headers.csp_missing'),
    'Strict-Transport-Security': check('Strict-Transport-Security', 'strict-transport-security', 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains', Severity.HIGH,   'headers.hsts_missing'),
    'X-Frame-Options':           check('X-Frame-Options',           'x-frame-options',           'Add: X-Frame-Options: DENY',                                         Severity.MEDIUM, 'headers.x_frame_options_missing'),
    'X-Content-Type-Options':    check('X-Content-Type-Options',    'x-content-type-options',    'Add: X-Content-Type-Options: nosniff',                               Severity.LOW,    'headers.x_content_type_missing'),
    'Referrer-Policy':           check('Referrer-Policy',           'referrer-policy',           'Add: Referrer-Policy: strict-origin-when-cross-origin',             Severity.LOW,    'headers.referrer_policy_missing'),
    'Permissions-Policy':        check('Permissions-Policy',        'permissions-policy',        'Add: Permissions-Policy: geolocation=(), microphone=()',             Severity.LOW,    'headers.permissions_policy_missing'),
    'X-XSS-Protection':          check('X-XSS-Protection',         'x-xss-protection',          'Add: X-XSS-Protection: 1; mode=block',                              Severity.LOW,    'headers.x_xss_protection_missing'),
  };

  // ── CSP Deep Analysis ────────────────────────────────────
  if (cspValue) {
    let cspIdx = 0;
    if (/unsafe-inline/i.test(cspValue)) {
      vulns.push({
        id: generateVulnId('CSP', ++cspIdx),
        title: "CSP allows 'unsafe-inline'",
        description: "Content-Security-Policy contains 'unsafe-inline', which negates XSS protection.",
        severity: Severity.HIGH, category: ScanCategory.HEADERS,
        evidence: `Content-Security-Policy: ${cspValue.slice(0, 120)}`,
        location: 'HTTP Response Headers',
        remediation: "Remove 'unsafe-inline'; use nonces or hashes for inline scripts.",
        detectedAt: Date.now(), detectedBy: 'rule',
        subCheckId: 'headers.csp_unsafe_inline', checkId: 'headers',
      });
    }
    if (/unsafe-eval/i.test(cspValue)) {
      vulns.push({
        id: generateVulnId('CSP', ++cspIdx),
        title: "CSP allows 'unsafe-eval'",
        description: "Content-Security-Policy contains 'unsafe-eval', permitting dynamic code execution.",
        severity: Severity.HIGH, category: ScanCategory.HEADERS,
        evidence: `Content-Security-Policy: ${cspValue.slice(0, 120)}`,
        location: 'HTTP Response Headers',
        remediation: "Remove 'unsafe-eval'; refactor code to avoid eval(), Function(), setTimeout(string).",
        detectedAt: Date.now(), detectedBy: 'rule',
        subCheckId: 'headers.csp_unsafe_eval', checkId: 'headers',
      });
    }
    if (!/default-src/i.test(cspValue)) {
      vulns.push({
        id: generateVulnId('CSP', ++cspIdx),
        title: 'CSP missing default-src directive',
        description: 'No default-src fallback — unspecified resource types are unrestricted.',
        severity: Severity.MEDIUM, category: ScanCategory.HEADERS,
        evidence: `CSP present but no default-src: ${cspValue.slice(0, 80)}`,
        location: 'HTTP Response Headers',
        remediation: "Add default-src 'none' or default-src 'self' to your CSP.",
        detectedAt: Date.now(), detectedBy: 'rule',
        subCheckId: 'headers.csp_no_default_src', checkId: 'headers',
      });
    }
  }

  return { analysis, vulns };
}

// ─── Cookie Analysis ──────────────────────────────────────
function analyzeCookies(cookies: chrome.cookies.Cookie[]): {
  analysis: CookieAnalysis[]; vulns: Vulnerability[];
} {
  const vulns: Vulnerability[] = [];
  let idx = 0;

  const analysis: CookieAnalysis[] = cookies.map(cookie => {
    const issues: string[] = [];
    if (!cookie.httpOnly) issues.push('Missing HttpOnly flag');
    if (!cookie.secure)   issues.push('Missing Secure flag');
    if (!cookie.sameSite || cookie.sameSite === 'no_restriction') issues.push('Missing or weak SameSite');

    if (issues.length > 0) {
      const isSession = /sess|auth|token|jwt|login|user/i.test(cookie.name);
      vulns.push({
        id: generateVulnId('CKI', ++idx),
        title: `Insecure cookie: ${cookie.name}`,
        description: `Cookie "${cookie.name}" is missing security flags: ${issues.join(', ')}`,
        severity: isSession ? Severity.HIGH : Severity.MEDIUM,
        category: ScanCategory.COOKIES,
        evidence: `Set-Cookie: ${cookie.name}=...; (missing: ${issues.join(', ')})`,
        location: `Cookie: ${cookie.name}`,
        remediation: `Set flags: ${cookie.name}=...; HttpOnly; Secure; SameSite=Strict`,
        detectedAt: Date.now(), detectedBy: 'rule',
        subCheckId: isSession ? 'cookies.session_no_secure' : 'cookies.non_session_no_secure',
        checkId: 'cookies',
      });
    }

    const sm = cookie.sameSite;
    return {
      name:     cookie.name,
      httpOnly: cookie.httpOnly,
      secure:   cookie.secure,
      sameSite: sm === 'strict' ? 'Strict' : sm === 'lax' ? 'Lax' : sm === 'no_restriction' ? 'None' : null,
      hasPrefix: cookie.name.startsWith('__Secure-') || cookie.name.startsWith('__Host-'),
      issues,
    };
  });

  return { analysis, vulns };
}

// ─── Form Security Analysis ───────────────────────────────
function analyzeForms(dom: DOMScanResult, pageIsHTTPS: boolean): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  let idx = 0;

  for (const form of dom.forms) {
    if (form.submitsOverHTTP && form.hasPasswordField) {
      vulns.push({
        id: generateVulnId('FORM', ++idx),
        title: 'Password form submits over HTTP',
        description: `A login form submits credentials to "${form.action}" unencrypted.`,
        severity: Severity.CRITICAL, category: ScanCategory.FORMS,
        evidence: `<form action="${form.action}" method="${form.method}">`,
        location: form.selector,
        remediation: 'Change form action to HTTPS.',
        detectedAt: Date.now(), detectedBy: 'rule',
        subCheckId: 'auth.login_over_http', checkId: 'auth',
      });
    }
    if (form.hasPasswordField && form.hasAutocomplete && pageIsHTTPS) {
      vulns.push({
        id: generateVulnId('FORM', ++idx),
        title: 'Password field has autocomplete enabled',
        description: 'Password field allows browser autocomplete, risking credential exposure on shared devices.',
        severity: Severity.MEDIUM, category: ScanCategory.FORMS,
        evidence: `<input type="password"> without autocomplete="off"`,
        location: form.selector,
        remediation: 'Add autocomplete="off" to password fields and the form element.',
        detectedAt: Date.now(), detectedBy: 'rule',
        subCheckId: 'auth.autocomplete_on', checkId: 'auth',
      });
    }
    if (form.hasPasswordField && !form.hasCsrfToken) {
      vulns.push({
        id: generateVulnId('FORM', ++idx),
        title: 'Login form missing CSRF protection',
        description: 'No CSRF token found in this form. Cross-Site Request Forgery attacks may be possible.',
        severity: Severity.MEDIUM, category: ScanCategory.FORMS,
        evidence: `No hidden input with csrf/token/_token/authenticity in name found`,
        location: form.selector,
        remediation: 'Add a synchronizer CSRF token as a hidden field in all forms.',
        detectedAt: Date.now(), detectedBy: 'rule',
        subCheckId: 'csrf.no_token_in_form', checkId: 'csrf',
      });
    }
  }

  // DOM-based script vulnerabilities
  let scriptIdx = 0;
  for (const script of dom.scripts) {
    if (script.isSuspicious) {
      vulns.push({
        id: generateVulnId('SCR', ++scriptIdx),
        title: script.suspicionReason ?? 'Suspicious script detected',
        description: script.isInline
          ? 'Inline script contains XSS-like patterns.'
          : `Script loaded from suspicious domain: ${script.domain}`,
        severity: script.isInline ? Severity.HIGH : Severity.MEDIUM,
        category: ScanCategory.SCRIPTS,
        evidence: script.snippet ?? script.src ?? '',
        location: script.src ?? 'Inline script',
        remediation: 'Review this script. Apply strict CSP with nonces.',
        detectedAt: Date.now(), detectedBy: 'rule',
        subCheckId: script.isInline ? 'input.in_script_block' : 'scripts.suspicious_external',
        checkId: script.isInline ? 'input' : 'scripts',
      });
    }
  }

  // Hidden iframes
  let iframeIdx = 0;
  for (const iframe of dom.iframes) {
    if (iframe.isHidden) {
      vulns.push({
        id: generateVulnId('IFR', ++iframeIdx),
        title: 'Hidden iframe detected',
        description: `A hidden iframe is loading: ${iframe.src ?? '(no src)'}`,
        severity: Severity.HIGH, category: ScanCategory.ANOMALY,
        evidence: `<iframe src="${iframe.src}" style="display:none">`,
        location: iframe.src ?? 'Hidden iframe',
        remediation: 'Remove hidden iframes. Add X-Frame-Options header.',
        detectedAt: Date.now(), detectedBy: 'rule',
        subCheckId: 'dom.hidden_iframe', checkId: 'dom',
      });
    }
  }

  return vulns;
}

// ─── JWT Analysis ─────────────────────────────────────────
function analyzeJWTs(dom: DOMScanResult): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  let idx = 0;
  for (const jwt of dom.jwtTokens) {
    if (jwt.alg === 'none') {
      vulns.push({
        id: generateVulnId('JWT', ++idx),
        title: 'JWT with alg:none detected',
        description: `A JWT using algorithm "none" was found in ${jwt.location}. This completely disables signature verification.`,
        severity: Severity.CRITICAL, category: ScanCategory.JWT,
        evidence: `alg: "none" in token at ${jwt.location}`,
        location: jwt.location,
        remediation: 'Reject JWTs with alg:none. Enforce algorithm allowlisting server-side.',
        detectedAt: Date.now(), detectedBy: 'rule',
        subCheckId: 'tokens.jwt_alg_none', checkId: 'tokens',
      });
    } else if (jwt.alg === 'HS256' || jwt.alg === 'HS384' || jwt.alg === 'HS512') {
      vulns.push({
        id: generateVulnId('JWT', ++idx),
        title: `JWT using ${jwt.alg} (symmetric) found in client storage`,
        description: `A JWT signed with ${jwt.alg} is stored in ${jwt.location}. Symmetric keys are vulnerable to brute-force if weak.`,
        severity: Severity.HIGH, category: ScanCategory.JWT,
        evidence: `alg: "${jwt.alg}" in token at ${jwt.location}`,
        location: jwt.location,
        remediation: 'Use RS256/ES256 (asymmetric). Ensure symmetric secrets are ≥256 bits of entropy.',
        detectedAt: Date.now(), detectedBy: 'rule',
        subCheckId: 'tokens.jwt_in_localstorage', checkId: 'tokens',
      });
    } else if (jwt.alg) {
      vulns.push({
        id: generateVulnId('JWT', ++idx),
        title: `JWT token found in client storage (${jwt.alg})`,
        description: `A JWT (${jwt.alg}) is stored in ${jwt.location}. Verify it does not contain sensitive data.`,
        severity: Severity.LOW, category: ScanCategory.JWT,
        evidence: `Token at ${jwt.location}`,
        location: jwt.location,
        remediation: 'Prefer httpOnly cookies for token storage over localStorage/sessionStorage.',
        detectedAt: Date.now(), detectedBy: 'rule',
        subCheckId: 'tokens.jwt_in_localstorage', checkId: 'tokens',
      });
    }
  }
  return vulns;
}

// ─── Mixed Content Analysis ───────────────────────────────
function analyzeMixedContent(dom: DOMScanResult): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  let idx = 0;
  for (const item of dom.mixedContent) {
    vulns.push({
      id: generateVulnId('MXD', ++idx),
      title: `Mixed content: HTTP ${item.tag} on HTTPS page`,
      description: `An <${item.tag}> resource is loaded over HTTP on an HTTPS page, allowing MITM attacks.`,
      severity: Severity.MEDIUM, category: ScanCategory.MIXED_CONTENT,
      evidence: `<${item.tag} src="${item.url}">`,
      location: item.url,
      remediation: `Change the URL to HTTPS: ${item.url.replace('http://', 'https://')}`,
      detectedAt: Date.now(), detectedBy: 'rule',
      subCheckId: 'mixed_content.http_resource', checkId: 'mixed_content',
    });
  }
  return vulns;
}

// ─── Tracker Analysis ─────────────────────────────────────
function analyzeTrackers(dom: DOMScanResult): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  let idx = 0;
  const seen = new Set<string>();
  for (const tracker of dom.trackers) {
    if (seen.has(tracker.service)) continue;
    seen.add(tracker.service);
    vulns.push({
      id: generateVulnId('TRK', ++idx),
      title: `Third-party tracker: ${tracker.service}`,
      description: `${tracker.service} tracking script detected. User behavior data is being sent to a third party.`,
      severity: Severity.INFO, category: ScanCategory.TRACKERS,
      evidence: tracker.src.slice(0, 120),
      location: tracker.src.slice(0, 120),
      remediation: `Review necessity of ${tracker.service}. Add to CSP and inform users via Privacy Policy.`,
      detectedAt: Date.now(), detectedBy: 'rule',
      subCheckId: 'trackers.third_party', checkId: 'trackers',
    });
  }
  return vulns;
}

// ─── Server Version Disclosure ────────────────────────────
function analyzeServerDisclosure(headers: Record<string, string>): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  let idx = 0;
  const serverHeader  = headers['server'] ?? '';
  const poweredHeader = headers['x-powered-by'] ?? '';

  if (/\d+\.\d+/i.test(serverHeader)) {
    vulns.push({
      id: generateVulnId('SRV', ++idx),
      title: 'Server version disclosed',
      description: `The Server header reveals version information that aids targeted attacks.`,
      severity: Severity.LOW, category: ScanCategory.SERVER_INFO,
      evidence: `Server: ${serverHeader}`,
      location: 'HTTP Response Headers',
      remediation: 'Configure the server to suppress or genericize the Server header.',
      detectedAt: Date.now(), detectedBy: 'rule',
      subCheckId: 'headers.server_version_exposed', checkId: 'headers',
    });
  }
  if (poweredHeader) {
    vulns.push({
      id: generateVulnId('SRV', ++idx),
      title: 'Technology stack disclosed via X-Powered-By',
      description: `X-Powered-By reveals the server-side technology: "${poweredHeader}"`,
      severity: Severity.LOW, category: ScanCategory.SERVER_INFO,
      evidence: `X-Powered-By: ${poweredHeader}`,
      location: 'HTTP Response Headers',
      remediation: 'Remove X-Powered-By header. In Express: app.disable("x-powered-by").',
      detectedAt: Date.now(), detectedBy: 'rule',
      subCheckId: 'headers.x_powered_by_exposed', checkId: 'headers',
    });
  }
  return vulns;
}

// ─── Phishing Indicators (rule-based, passive) ────────────
function analyzePhishingIndicators(dom: DOMScanResult, url: string): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  let idx = 0;
  let domain = '';
  try { domain = new URL(url).hostname; } catch { return []; }

  for (const form of dom.forms) {
    if (form.hasPasswordField && form.action) {
      try {
        const actionDomain = new URL(form.action).hostname;
        if (actionDomain && actionDomain !== domain) {
          vulns.push({
            id: generateVulnId('PHI', ++idx),
            title: 'Login form submits to different domain',
            description: `A password form on "${domain}" submits credentials to "${actionDomain}" — a classic phishing technique.`,
            severity: Severity.HIGH, category: ScanCategory.PHISHING,
            evidence: `action="${form.action}"`,
            location: form.selector,
            remediation: 'Verify this is intentional. If not, this may indicate page tampering.',
            detectedAt: Date.now(), detectedBy: 'rule',
            subCheckId: 'phishing.cross_domain_form', checkId: 'phishing',
          });
        }
      } catch { /* */ }
    }
  }

  if (dom.faviconUrl) {
    try {
      const faviconDomain = new URL(dom.faviconUrl).hostname;
      if (faviconDomain !== domain) {
        vulns.push({
          id: generateVulnId('PHI', ++idx),
          title: 'Favicon loaded from different domain',
          description: `Page favicon is hosted on "${faviconDomain}" while page is on "${domain}". May indicate domain spoofing.`,
          severity: Severity.MEDIUM, category: ScanCategory.PHISHING,
          evidence: `favicon href="${dom.faviconUrl}"`,
          location: dom.faviconUrl,
          remediation: 'Host all page assets on the same domain.',
          detectedAt: Date.now(), detectedBy: 'rule',
          subCheckId: 'phishing.cross_domain_favicon', checkId: 'phishing',
        });
      }
    } catch { /* */ }
  }

  return vulns;
}

// ─── ML Predictions → Vulnerabilities ────────────────────
function mlToVulns(preds: MLPrediction[]): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  let idx = 0;
  for (const p of preds) {
    if (!p.isMalicious) continue;
    const pct = (p.confidence * 100).toFixed(1);
    if (p.modelName === 'xss') {
      vulns.push({
        id: generateVulnId('ML-XSS', ++idx),
        title: 'XSS Payload Detected (AI)',
        description: `AI model detected a potential XSS payload with ${pct}% confidence.`,
        severity: p.confidence > 0.85 ? Severity.CRITICAL : Severity.HIGH,
        category: ScanCategory.XSS,
        evidence: `XSS model confidence: ${pct}%`,
        location: 'Inline scripts / URL parameters / form inputs',
        remediation: 'Sanitize all user input. Apply CSP. Use textContent instead of innerHTML.',
        detectedAt: Date.now(), detectedBy: 'ml', confidence: p.confidence,
        subCheckId: 'ml.xss_detected', checkId: 'ml',
      });
    }
    if (p.modelName === 'phishing') {
      vulns.push({
        id: generateVulnId('ML-PHI', ++idx),
        title: 'Phishing Page Detected (AI)',
        description: `AI model classified this URL as phishing with ${pct}% confidence.`,
        severity: p.confidence > 0.85 ? Severity.CRITICAL : Severity.HIGH,
        category: ScanCategory.PHISHING,
        evidence: `Phishing model confidence: ${pct}%`,
        location: 'Page URL',
        remediation: 'Do not enter credentials. Report via Google Safe Browsing.',
        detectedAt: Date.now(), detectedBy: 'ml', confidence: p.confidence,
        subCheckId: 'ml.phishing_detected', checkId: 'ml',
      });
    }
    if (p.modelName === 'anomaly') {
      const mse = (p.features['mse_score'] as number | undefined)?.toFixed(4) ?? '?';
      vulns.push({
        id: generateVulnId('ML-ANO', ++idx),
        title: 'Behavioral Anomaly Detected (AI)',
        description: `Autoencoder detected abnormal page structure (MSE: ${mse}). Possible hidden iframes, script injection, or obfuscation.`,
        severity: Severity.MEDIUM, category: ScanCategory.ANOMALY,
        evidence: `Reconstruction error (${mse}) exceeds anomaly threshold`,
        location: 'Page DOM structure',
        remediation: 'Investigate hidden iframes, unusual script loading, and obfuscated code.',
        detectedAt: Date.now(), detectedBy: 'ml', confidence: p.confidence,
        subCheckId: 'ml.anomaly_detected', checkId: 'ml',
      });
    }
  }
  return vulns;
}

// ─── ML Context Enrichment ────────────────────────────────
function enrichMLPredictions(preds: MLPrediction[], dom: DOMScanResult): MLPrediction[] {
  return preds.map(p => {
    if (p.modelName === 'xss') {
      const inputCount  = dom.inputs.length;
      const xssVectors  = dom.inputs.filter(i => i.hasXSSPayload).length +
                          dom.scripts.filter(s => s.isSuspicious && s.isInline).length;
      return {
        ...p,
        analysisContext:  `Analyzed ${inputCount} inputs and ${dom.scripts.filter(s => s.isInline).length} inline scripts`,
        findingsSummary:  xssVectors > 0
          ? `${xssVectors} potential XSS vector${xssVectors > 1 ? 's' : ''} found`
          : p.isMalicious ? '1 potential XSS vector found' : 'No XSS vectors detected',
      };
    }
    if (p.modelName === 'phishing') {
      const indicators = dom.forms.filter(f => f.hasPasswordField).length +
                         (dom.faviconUrl ? 1 : 0);
      return {
        ...p,
        analysisContext:  `Analyzed domain, ${dom.forms.length} forms, and page structure`,
        findingsSummary:  indicators > 0
          ? `${indicators} phishing indicator${indicators > 1 ? 's' : ''} found`
          : p.isMalicious ? 'Phishing pattern detected in URL structure' : 'No phishing indicators detected',
      };
    }
    if (p.modelName === 'anomaly') {
      const anomalies = [
        dom.scripts.length > 20 ? `${dom.scripts.length} scripts (>20)` : '',
        dom.iframes.length > 5  ? `${dom.iframes.length} iframes (>5)` : '',
        dom.forms.length > 3    ? `${dom.forms.length} forms (>3)` : '',
        dom.links.filter(l => l.isExternal).length > 15
          ? `${dom.links.filter(l => l.isExternal).length} external links (>15)` : '',
      ].filter(Boolean);
      return {
        ...p,
        analysisContext:  `Baseline comparison of ${dom.scripts.length} scripts, ${dom.iframes.length} iframes, ${dom.forms.length} forms`,
        findingsSummary:  anomalies.length > 0
          ? `${anomalies.length} anomal${anomalies.length > 1 ? 'ies' : 'y'}: ${anomalies.join('; ')}`
          : p.isMalicious ? 'Structural anomaly detected (elevated reconstruction error)' : 'Page structure within normal baseline',
      };
    }
    return p;
  });
}

// ─── Sequential Visible Tab Scanner ──────────────────────

const SCAN_PATHS: Array<{
  path: string; severity: Severity; title: string; description: string;
}> = [
  { path: '/robots.txt',  severity: Severity.INFO,     title: 'robots.txt found',                 description: 'Robots exclusion file present. Disallowed paths may reveal sensitive directories to attackers.' },
  { path: '/sitemap.xml', severity: Severity.INFO,     title: 'sitemap.xml found',                description: 'XML sitemap discovered — contains the full URL index of this site.' },
  { path: '/.env',        severity: Severity.CRITICAL, title: '.env file exposed',                description: 'Environment config file is publicly accessible. Likely contains DB credentials, API keys, and secrets.' },
  { path: '/.git/config', severity: Severity.CRITICAL, title: 'Git repository config accessible', description: 'Source control config is readable. Full repository history may be downloadable via /.git/' },
  { path: '/admin',       severity: Severity.HIGH,     title: 'Admin panel accessible',           description: 'Administration interface is reachable from the public internet without an authentication gate.' },
  { path: '/login',       severity: Severity.MEDIUM,   title: 'Login page detected',              description: 'Authentication page found. Verify brute-force protection, rate limiting, and MFA policies.' },
  { path: '/api',         severity: Severity.MEDIUM,   title: 'API endpoint accessible',          description: 'API root is publicly reachable. Verify authentication is enforced on all sub-endpoints.' },
  { path: '/config.json', severity: Severity.HIGH,     title: 'config.json exposed',              description: 'Application configuration file is publicly readable. May contain DB connections or API keys.' },
  { path: '/backup.zip',  severity: Severity.CRITICAL, title: 'Backup archive accessible',        description: 'A backup archive is publicly downloadable. May contain full source code or a database dump.' },
  { path: '/wp-admin',    severity: Severity.HIGH,     title: 'WordPress admin panel detected',   description: 'WordPress admin dashboard is reachable. Confirm strong credentials and 2FA are enforced.' },
  { path: '/.htaccess',   severity: Severity.HIGH,     title: '.htaccess configuration exposed',  description: 'Apache config file is readable. May reveal rewrite rules, authentication logic, and directory layout.' },
  { path: '/phpinfo.php', severity: Severity.CRITICAL, title: 'phpinfo() page accessible',        description: 'PHP debug page is publicly accessible. Exposes server paths, installed modules, and PHP config values.' },
];

const PATH_SUB_CHECK: Record<string, { subCheckId: string; checkId: string }> = {
  '/robots.txt':  { subCheckId: 'files.robots_reveals_paths',   checkId: 'files'   },
  '/sitemap.xml': { subCheckId: 'files.sitemap_exposes_routes', checkId: 'files'   },
  '/.env':        { subCheckId: 'files.env_accessible',         checkId: 'files'   },
  '/.git/config': { subCheckId: 'files.git_config_accessible',  checkId: 'files'   },
  '/admin':       { subCheckId: 'routes.admin_no_auth',         checkId: 'routes'  },
  '/login':       { subCheckId: 'routes.login_page_exposed',    checkId: 'routes'  },
  '/api':         { subCheckId: 'routes.api_no_auth',           checkId: 'routes'  },
  '/config.json': { subCheckId: 'files.source_map_accessible',  checkId: 'files'   },
  '/backup.zip':  { subCheckId: 'files.backup_accessible',      checkId: 'files'   },
  '/wp-admin':    { subCheckId: 'routes.admin_no_auth',         checkId: 'routes'  },
  '/.htaccess':   { subCheckId: 'files.htaccess_accessible',    checkId: 'files'   },
  '/phpinfo.php': { subCheckId: 'files.phpinfo_accessible',     checkId: 'files'   },
};

const PATH_REMEDIATIONS: Record<string, string> = {
  '/robots.txt':  'Review disallowed paths — they may hint at sensitive directories. No immediate action required if paths are already protected.',
  '/sitemap.xml': 'Ensure the sitemap only lists pages intended for public indexing.',
  '/.env':        'Move .env above the webroot. Block via nginx: "location ~ /\\.env { deny all; }" or Apache: "deny from all" inside <Files .env>.',
  '/.git/config': 'Block /.git in server config: "location ~ /\\.git { deny all; }" — never deploy .git directory to production servers.',
  '/admin':       'Restrict /admin by IP allowlist, require VPN access, or move to a non-standard path. Enforce MFA on all admin accounts.',
  '/login':       'Implement account lockout after failed attempts, CAPTCHA on high-failure IPs, and rate limiting on the login endpoint.',
  '/api':         'Ensure all API endpoints require authentication. Disable unauthenticated listing of the API root.',
  '/config.json': 'Move config files above the webroot and deny web access: "location ~ /config\\.json { deny all; }"',
  '/backup.zip':  'Remove backup files from the webroot immediately. Store backups in a non-web-accessible location or object storage.',
  '/wp-admin':    'Restrict /wp-admin to known IPs via .htaccess or Cloudflare firewall rule. Enforce 2FA on all WordPress accounts.',
  '/.htaccess':   'Deny .htaccess access: add "<Files .htaccess>\\nRequire all denied\\n</Files>" to your Apache VirtualHost config.',
  '/phpinfo.php': 'Delete phpinfo.php from production. Never deploy PHP debug pages to live servers.',
};

function waitForTabLoad(tabId: number, timeoutMs = 12000): Promise<void> {
  return new Promise(resolve => {
    const timer = setTimeout(() => {
      chrome.tabs.onUpdated.removeListener(listener);
      resolve();
    }, timeoutMs);

    const listener = (id: number, info: chrome.tabs.TabChangeInfo) => {
      if (id === tabId && info.status === 'complete') {
        clearTimeout(timer);
        chrome.tabs.onUpdated.removeListener(listener);
        setTimeout(resolve, 350);
      }
    };
    chrome.tabs.onUpdated.addListener(listener);
  });
}

async function getTabPageInfo(tabId: number): Promise<{ status: number; bodyLength: number }> {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        const nav = performance.getEntriesByType('navigation')[0] as any;
        return {
          status:     nav?.responseStatus ?? 0,
          bodyLength: document.body?.textContent?.length ?? 0,
        };
      },
    });
    return results[0]?.result ?? { status: 0, bodyLength: 0 };
  } catch {
    return { status: 0, bodyLength: 0 };
  }
}

function broadcastTabProgress(
  scanId: string, phase: string, step: number,
  channelNum: number, totalChannels: number, path: string,
) {
  chrome.runtime.sendMessage({
    type: 'SCAN_PROGRESS',
    payload: { scanId, phase, step, channelNum, totalChannels, path },
  } as ExtensionMessage).catch(() => {});
}

async function runTabScan(
  baseUrl: string,
  scanId: string,
  originalTabId: number,
  signal: AbortSignal,
): Promise<Vulnerability[]> {
  let origin = '';
  try { origin = new URL(baseUrl).origin; } catch { return []; }

  const total       = SCAN_PATHS.length;
  const allFindings: Vulnerability[] = [];

  // Steps 0-1: TARGET ACQUIRED + INITIALIZING SCAN PROTOCOLS
  broadcastTabProgress(scanId, 'init', 0, 0, total, '');
  await delay(700);
  broadcastTabProgress(scanId, 'init', 1, 0, total, '');
  await delay(700);

  for (let i = 0; i < SCAN_PATHS.length; i++) {
    if (signal.aborted) break;

    const meta       = SCAN_PATHS[i];
    const url        = `${origin}${meta.path}`;
    const channelNum = i + 1;

    // Step 2: OPENING TARGET CHANNEL
    broadcastTabProgress(scanId, 'TAB_OPEN', 2, channelNum, total, meta.path);

    let tabId: number | null = null;

    try {
      const tab = await chrome.tabs.create({ url, active: true });
      tabId = tab.id!;

      await waitForTabLoad(tabId);

      // Inject the blue overlay (Feature 3)
      try {
        await chrome.scripting.executeScript({ target: { tabId }, files: ['content/overlay.js'] });
        await delay(180);
        await chrome.tabs.sendMessage(tabId, {
          type: 'OVERLAY_INIT',
          payload: { channelNum, totalChannels: total, path: meta.path, url },
        });
      } catch { /* CSP or chrome:// pages may block injection */ }

      // Steps 3-7: analysis phases — 5 × 900 ms = 4.5 s total
      const analysisSteps = [
        { step: 3, name: 'ANALYZING PAGE STRUCTURE' },
        { step: 4, name: 'EXTRACTING HEADERS & METADATA' },
        { step: 5, name: 'SCANNING FOR VULNERABILITIES' },
        { step: 6, name: 'CROSS-REFERENCING THREAT DATABASE' },
        { step: 7, name: 'COMPILING FINDINGS' },
      ];

      for (const { step, name } of analysisSteps) {
        if (signal.aborted) break;
        broadcastTabProgress(scanId, 'TAB_STEP', step, channelNum, total, meta.path);
        try { await chrome.tabs.sendMessage(tabId, { type: 'OVERLAY_STEP', step: name }); } catch { }
        await delay(900);
      }

      // Passive read — uses already-loaded PerformanceNavigationTiming (no new request)
      const pageInfo = await getTabPageInfo(tabId);
      const status   = pageInfo.status;
      const hasBody  = pageInfo.bodyLength > 80;

      // Extra dwell so user can clearly see the tab (~5 s total per tab)
      await delay(500);

      // Generate findings
      const pathSC = PATH_SUB_CHECK[meta.path] ?? { subCheckId: 'uncategorized', checkId: 'files' };
      if (status === 200 || (status === 0 && hasBody)) {
        allFindings.push({
          id:          generateVulnId('TAB', i + 1),
          title:       meta.title,
          description: meta.description,
          severity:    meta.severity,
          category:    (meta.severity === Severity.CRITICAL || meta.severity === Severity.HIGH)
            ? ScanCategory.SENSITIVE_FILES : ScanCategory.SERVER_INFO,
          evidence:    `HTTP 200 — ${url} (${pageInfo.bodyLength} bytes)`,
          location:    url,
          remediation: PATH_REMEDIATIONS[meta.path] ?? 'Restrict access via server configuration.',
          detectedAt:  Date.now(),
          detectedBy:  'rule',
          subCheckId:  pathSC.subCheckId,
          checkId:     pathSC.checkId,
        });
      } else if (status === 403) {
        if (meta.severity === Severity.CRITICAL || meta.severity === Severity.HIGH) {
          allFindings.push({
            id:          generateVulnId('TAB', i + 1),
            title:       `${meta.title} (path exists — access forbidden)`,
            description: `${meta.path} returned 403. The resource exists on the server but access is currently restricted.`,
            severity:    Severity.LOW,
            category:    ScanCategory.SENSITIVE_FILES,
            evidence:    `HTTP 403 at ${url}`,
            location:    url,
            remediation: 'Remove the file entirely rather than relying solely on 403 for protection.',
            detectedAt:  Date.now(),
            detectedBy:  'rule',
            subCheckId:  pathSC.subCheckId,
            checkId:     pathSC.checkId,
          });
        }
      }

    } catch (err) {
      console.warn(`[CyberINTEL] Tab scan error on ${meta.path}:`, err);
    } finally {
      // Step 8: CLOSING CHANNEL
      broadcastTabProgress(scanId, 'TAB_CLOSED', 8, channelNum, total, meta.path);
      if (tabId !== null) {
        try { await chrome.tabs.sendMessage(tabId, { type: 'OVERLAY_REMOVE' }); } catch { }
        await delay(250);
        try { await chrome.tabs.remove(tabId); } catch { }
      }
    }
  }

  // Step 9: SCAN COMPLETE
  broadcastTabProgress(scanId, 'SCAN_COMPLETE', 9, total, total, '');
  await delay(600);

  // Return focus to the original tab
  try { await chrome.tabs.update(originalTabId, { active: true }); } catch { }

  return allFindings;
}

// ─── Full Scan ────────────────────────────────────────────
async function runFullScan(
  tab: chrome.tabs.Tab,
  signal: AbortSignal,
  onProgress: (stage: string, pct: number, msg: string, data?: ProgressData) => void,
  authToken: string | undefined,
  scanId: string,
  mode: 'quick' | 'full',
  sensitivity: 'low' | 'medium' | 'high' = 'medium',
): Promise<ScanResult> {
  const startTime = Date.now();
  const url       = tab.url || '';
  const isHTTPS   = url.startsWith('https://');
  let domain      = '';
  try { domain = new URL(url).hostname; } catch { domain = url; }

  // Accumulated sensitivity-filtered findings across all stages
  const cumVulns: Vulnerability[] = [];
  let domResult:      DOMScanResult | null = null;
  let cookies:        CookieAnalysis[]     = [];
  let headerAnalysis: SecurityHeaders | null = null;
  let rawHeaders:     Record<string, string> = {};
  let aborted       = false;
  let mlPredictions: MLPrediction[] = [];

  // Sensitivity allowlist
  const sensitivityMap: Record<string, Severity[]> = {
    low:    [Severity.CRITICAL, Severity.HIGH],
    medium: [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM],
    high:   [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO],
  };
  const allowed = sensitivityMap[sensitivity] ?? sensitivityMap.high;
  const applyFilter = (v: Vulnerability[]) => v.filter(x => allowed.includes(x.severity));

  // Emit a completed stage: filter findings, accumulate, broadcast with live score/counts
  const emitStage = (stage: string, pct: number, msg: string, stageVulns: Vulnerability[]) => {
    const filtered = applyFilter(stageVulns);
    cumVulns.push(...filtered);
    const score  = calculateSecurityScore(cumVulns);
    const grade  = scoreToGrade(score);
    const counts = countBySeverity(cumVulns);
    onProgress(stage, pct, msg, {
      addedFindings: filtered, currentScore: score, currentGrade: grade, currentCounts: counts,
    });
  };

  // ── INIT ─────────────────────────────────────────────────
  onProgress('init', 2, 'Target acquired. Initializing scan protocols...', {
    addedFindings: [], currentScore: 100, currentGrade: 'A',
    currentCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  });
  await delay(220);

  // ── STAGE 1 · DOM ─────────────────────────────────────────
  // Covers: forms, scripts/iframes, JWT, mixed content
  if (!signal.aborted) {
    onProgress('dom', 5, 'Scanning DOM: scripts, forms, storage, and client-side code...');
    await delay(180);

    if (tab.id) {
      try { domResult = await extractDOM(tab.id); }
      catch (err) { console.warn('[CyberINTEL-AI] DOM extraction failed:', err); }
    }

    const domVulns: Vulnerability[] = [];
    if (domResult) {
      domVulns.push(...analyzeForms(domResult, isHTTPS));
      if (mode === 'full') {
        domVulns.push(...analyzeJWTs(domResult));
        domVulns.push(...analyzeMixedContent(domResult));
      }
    }

    const domHits = applyFilter(domVulns).length;
    emitStage('dom', mode === 'full' ? 26 : 34,
      domHits > 0
        ? `DOM audit — ${domHits} finding${domHits !== 1 ? 's' : ''} detected`
        : 'DOM audit complete — no client-side issues',
      domVulns,
    );
    await delay(480);
  }
  if (signal.aborted) aborted = true;

  // ── STAGE 2 · TRANSPORT ───────────────────────────────────
  // Covers: HTTP headers + SSL/HTTPS check
  if (!aborted) {
    onProgress('transport', mode === 'full' ? 28 : 36,
      'Inspecting transport security: HTTP headers, SSL/TLS...');
    await delay(150);

    try {
      const reqHeaders: Record<string, string> = {};
      if (authToken) reqHeaders['Authorization'] = `Bearer ${authToken}`;
      const res = await fetch(url, { method: 'HEAD', cache: 'no-store', signal, headers: reqHeaders });
      res.headers.forEach((v, k) => { rawHeaders[k.toLowerCase()] = v; });
    } catch { /* CORS or abort — rawHeaders stays empty */ }

    const transportVulns: Vulnerability[] = [];
    if (Object.keys(rawHeaders).length > 0) {
      const { analysis, vulns } = analyzeHeaders(rawHeaders);
      headerAnalysis = analysis;
      transportVulns.push(...vulns);
    } else {
      transportVulns.push({
        id: generateVulnId('HDR', 0),
        title: 'HTTP response headers not accessible',
        description: 'Security headers could not be read from the extension context (CORS policy). Verify them in DevTools → Network → Response Headers.',
        severity: Severity.INFO, category: ScanCategory.HEADERS,
        evidence: 'HEAD request returned no readable headers',
        location: 'HTTP Response Headers',
        remediation: 'Use browser DevTools or a server-side scanner to verify security headers.',
        detectedAt: Date.now(), detectedBy: 'rule',
        subCheckId: 'headers.cors_blocked', checkId: 'headers',
      });
    }
    if (!isHTTPS) {
      transportVulns.push({
        id: generateVulnId('SSL', 1),
        title: 'Site not served over HTTPS',
        description: 'All traffic is transmitted unencrypted. Credentials, sessions, and data are exposed to interception.',
        severity: Severity.CRITICAL, category: ScanCategory.SSL,
        evidence: `URL: ${url}`, location: url,
        remediation: 'Install a TLS certificate (Let\'s Encrypt is free) and redirect all HTTP traffic to HTTPS.',
        detectedAt: Date.now(), detectedBy: 'rule',
        subCheckId: 'ssl.no_https', checkId: 'ssl',
      });
    }

    const tHits = applyFilter(transportVulns).length;
    emitStage('transport', mode === 'full' ? 46 : 64,
      tHits > 0
        ? `Transport audit — ${tHits} finding${tHits !== 1 ? 's' : ''} detected`
        : 'Transport audit complete — headers and SSL look good',
      transportVulns,
    );
    if (signal.aborted) aborted = true;
    await delay(380);
  }

  // ── STAGE 3 · COOKIES ─────────────────────────────────────
  if (!aborted) {
    onProgress('cookies', mode === 'full' ? 48 : 66,
      'Auditing cookie security flags...');
    await delay(150);

    const cookieVulns: Vulnerability[] = [];
    try {
      const chromeCookies = await chrome.cookies.getAll({ url });
      const { analysis: ca, vulns: cv } = analyzeCookies(chromeCookies);
      cookies = ca;
      cookieVulns.push(...cv);
    } catch { /* unavailable */ }

    const cHits = applyFilter(cookieVulns).length;
    emitStage('cookies', mode === 'full' ? 58 : 84,
      cHits > 0
        ? `Cookie audit — ${cHits} insecure cookie${cHits !== 1 ? 's' : ''} found`
        : 'Cookie audit complete — all cookies correctly configured',
      cookieVulns,
    );
    if (signal.aborted) aborted = true;
    await delay(380);
  }

  if (mode === 'full') {
    // ── STAGE 4 · NETWORK ──────────────────────────────────
    // Covers: trackers, server disclosure, phishing
    if (!aborted) {
      onProgress('network', 60,
        'Checking third-party trackers, server disclosure, and phishing indicators...');
      await delay(150);

      const networkVulns: Vulnerability[] = [];
      if (domResult) {
        networkVulns.push(...analyzeTrackers(domResult));
        networkVulns.push(...analyzePhishingIndicators(domResult, url));
      }
      if (Object.keys(rawHeaders).length > 0) {
        networkVulns.push(...analyzeServerDisclosure(rawHeaders));
      }

      const nHits = applyFilter(networkVulns).length;
      emitStage('network', 72,
        nHits > 0
          ? `Network audit — ${nHits} finding${nHits !== 1 ? 's' : ''} detected`
          : 'Network audit complete — no tracker or disclosure issues',
        networkVulns,
      );
      if (signal.aborted) aborted = true;
      await delay(380);
    }

    // ── STAGE 5 · AI / ML ──────────────────────────────────
    if (!aborted && domResult) {
      onProgress('ml', 74, 'Running AI/ML threat detection models...');

      try {
        await ensureOffscreen();
        const mlResp = await Promise.race([
          chrome.runtime.sendMessage({
            type: 'OFFSCREEN_ML_REQUEST',
            payload: { url, dom: domResult },
          } as ExtensionMessage),
          new Promise<never>((_, rej) => setTimeout(() => rej(new Error('ML timeout')), 12000)),
        ]) as { payload?: MLPrediction[]; error?: string };

        const rawPreds: MLPrediction[] = mlResp?.payload ?? [];
        mlPredictions = enrichMLPredictions(rawPreds, domResult);
        const mlVulns = mlToVulns(mlPredictions);

        const mHits = applyFilter(mlVulns).length;
        emitStage('ml', 96,
          mHits > 0
            ? `AI analysis — ${mHits} ML threat${mHits !== 1 ? 's' : ''} detected`
            : 'AI analysis complete — no threats detected',
          mlVulns,
        );
      } catch (err) {
        console.warn('[CyberINTEL-AI] ML inference error:', err);
        onProgress('ml', 96, 'AI analysis complete (models unavailable)');
      }
      if (signal.aborted) aborted = true;
      await delay(300);
    }
  }

  // ── DONE ─────────────────────────────────────────────────
  const finalScore  = calculateSecurityScore(cumVulns);
  const finalGrade  = scoreToGrade(finalScore);
  const finalCounts = countBySeverity(cumVulns);
  onProgress('done', 100,
    aborted
      ? 'Scan stopped — partial results available'
      : `Report complete — ${cumVulns.length} finding${cumVulns.length !== 1 ? 's' : ''} total`,
    { addedFindings: [], currentScore: finalScore, currentGrade: finalGrade, currentCounts: finalCounts },
  );

  return {
    id: scanId, url, domain,
    scannedAt: startTime,
    scanDurationMs: Date.now() - startTime,
    securityScore: finalScore,
    grade: finalGrade,
    headers: headerAnalysis,
    ssl: { isHTTPS, validCert: isHTTPS, expiryDate: null, issuer: null, protocol: null, grade: null },
    cookies, dom: domResult,
    vulnerabilities: cumVulns,
    mlPredictions,
    counts: finalCounts,
    status: aborted ? 'aborted' : 'complete',
  };
}

// ─── Storage ──────────────────────────────────────────────
async function saveToHistory(scan: ScanResult): Promise<void> {
  const data = await chrome.storage.local.get('scanHistory');
  const history: ScanResult[] = data.scanHistory ?? [];
  history.unshift(scan);
  if (history.length > 50) history.pop();
  await chrome.storage.local.set({ scanHistory: history });
}

async function syncToWebApp(scan: ScanResult, backendUrl: string): Promise<void> {
  await fetch(`${backendUrl}/api/v1/scans/import/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      url: scan.url,
      domain: scan.domain,
      vulnerabilities: scan.vulnerabilities,
      securityScore: scan.securityScore,
      grade: scan.grade,
      scannedAt: scan.scannedAt,
      scanDurationMs: scan.scanDurationMs,
      counts: scan.counts,
      status: scan.status,
    }),
  });
}

// ─── Message Handler ──────────────────────────────────────
chrome.runtime.onMessage.addListener((message: ExtensionMessage, sender, sendResponse) => {
  switch (message.type) {

    case 'SCAN_REQUEST': {
      (async () => {
        const tabId  = sender.tab?.id ?? (message.tabId as number);
        const tab    = await chrome.tabs.get(tabId);
        const scanId = `scan-${Date.now()}-${tabId}`;
        const ctrl   = new AbortController();
        activeScans.set(scanId, ctrl);

        chrome.runtime.sendMessage({
          type: 'SCAN_STARTED', payload: { scanId },
        } as ExtensionMessage).catch(() => {});

        const payload = message.payload as {
          authToken?: string;
          mode?: 'quick' | 'full' | 'threat';
        } | null;

        const mode      = payload?.mode ?? 'quick';
        const authToken = payload?.authToken;

        const _sd       = await chrome.storage.local.get('settings');
        const _settings = { ...DEFAULT_SETTINGS, ...(_sd.settings ?? {}) } as typeof DEFAULT_SETTINGS;

        // Open target page with overlay if setting is enabled
        let overlayTabId: number | null = null;
        if ((_settings as any).openPageDuringScan && tab.url) {
          try {
            const overlayTab = await chrome.tabs.create({ url: tab.url, active: false });
            overlayTabId = overlayTab.id ?? null;
            await delay(2000);
            if (overlayTabId) {
              await chrome.scripting.executeScript({
                target: { tabId: overlayTabId },
                files: ['content/overlay.js'],
              });
            }
          } catch { overlayTabId = null; }
        }

        try {
          let result: ScanResult;

          if (mode === 'threat') {
            const scanStart  = Date.now();
            const stopKA     = swKeepAlive();
            let threatFindings: Vulnerability[] = [];
            try {
              threatFindings = await runTabScan(
                tab.url || '', scanId, tabId, ctrl.signal,
              );
            } finally {
              stopKA();
            }
            const score  = calculateSecurityScore(threatFindings);
            const grade  = scoreToGrade(score);
            let domainStr = '';
            try { domainStr = new URL(tab.url || '').hostname; } catch { domainStr = tab.url || ''; }

            result = {
              id: scanId, url: tab.url || '', domain: domainStr,
              scannedAt: scanStart, scanDurationMs: Date.now() - scanStart,
              securityScore: score, grade,
              headers: null,
              ssl: { isHTTPS: (tab.url || '').startsWith('https://'), validCert: false, expiryDate: null, issuer: null, protocol: null, grade: null },
              cookies: [], dom: null,
              vulnerabilities: threatFindings, mlPredictions: [],
              counts: countBySeverity(threatFindings),
              status: ctrl.signal.aborted ? 'aborted' : 'complete',
            };
          } else {
            const onProg = (stage: string, pct: number, msg: string, data?: ProgressData) => {
              broadcastProgress(scanId, stage, pct, msg, data);
              if (overlayTabId) {
                chrome.tabs.sendMessage(overlayTabId, {
                  type: 'OVERLAY_PROGRESS', payload: { stage, pct, message: msg },
                }).catch(() => {});
                if (data?.addedFindings?.length) {
                  for (const f of data.addedFindings) {
                    chrome.tabs.sendMessage(overlayTabId, {
                      type: 'OVERLAY_FINDING', payload: f,
                    }).catch(() => {});
                  }
                }
              }
            };
            result = await runFullScan(tab, ctrl.signal, onProg, authToken, scanId, mode, _settings.scanSensitivity);
          }

          if (overlayTabId) {
            chrome.tabs.sendMessage(overlayTabId, { type: 'OVERLAY_REMOVE' }).catch(() => {});
          }
          await saveToHistory(result);
          if (_settings.backendUrl) {
            syncToWebApp(result, _settings.backendUrl).catch(() => {});
          }
          sendResponse({ type: 'SCAN_RESULT', payload: result });
        } catch (err) {
          sendResponse({ type: 'SCAN_RESULT', error: String(err) });
        } finally {
          activeScans.delete(scanId);
        }
      })();
      return true;
    }

    case 'SCAN_ABORT': {
      const { scanId } = message.payload as { scanId: string };
      const ctrl = activeScans.get(scanId);
      if (ctrl) { ctrl.abort(); activeScans.delete(scanId); }
      sendResponse({ type: 'SCAN_ABORTED' });
      return false;
    }

    case 'GET_LATEST_SCAN':
      (async () => {
        const data = await chrome.storage.local.get('scanHistory');
        const h: ScanResult[] = data.scanHistory ?? [];
        sendResponse({ type: 'SCAN_RESULT', payload: h[0] ?? null });
      })();
      return true;

    case 'GET_SCAN_HISTORY':
      (async () => {
        const data = await chrome.storage.local.get('scanHistory');
        sendResponse({ type: 'SCAN_RESULT', payload: data.scanHistory ?? [] });
      })();
      return true;

    case 'MONITOR_EVENT':
      (async () => {
        const data   = await chrome.storage.local.get('monitorEvents');
        const events: MonitorEvent[] = data.monitorEvents ?? [];
        events.unshift(message.payload as MonitorEvent);
        if (events.length > 500) events.pop();
        await chrome.storage.local.set({ monitorEvents: events });
      })();
      return false;

    case 'ML_INFERENCE_REQUEST':
      (async () => {
        try {
          await ensureOffscreen();
          const result = await chrome.runtime.sendMessage({
            type: 'OFFSCREEN_ML_REQUEST', payload: message.payload,
          } as ExtensionMessage);
          sendResponse(result ?? { type: 'OFFSCREEN_ML_RESULT', payload: [] });
        } catch (err) {
          sendResponse({ type: 'OFFSCREEN_ML_RESULT', error: String(err), payload: [] });
        }
      })();
      return true;

    case 'MODELS_LOADED':
      chrome.storage.local.set({ modelStatus: message.payload });
      return false;

    case 'ML_STATUS_REQUEST':
      (async () => {
        try { await ensureOffscreen(); } catch { /* may already exist */ }
        const data = await chrome.storage.local.get('modelStatus');
        sendResponse({ type: 'ML_STATUS_RESULT', payload: data.modelStatus ?? null });
      })();
      return true;

    default:
      return false;
  }
});

// ─── Auto-Scan on Tab Load ────────────────────────────────
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  const url = tab.url || '';
  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') ||
      url.startsWith('about:') || url.startsWith('edge://')) return;

  const data = await chrome.storage.local.get('settings');
  const settings = { ...DEFAULT_SETTINGS, ...(data.settings ?? {}) };
  if (!settings.autoScanOnVisit) return;

  // Only auto-scan domains where the user has already given Tier 1 consent this session
  try {
    const domain      = new URL(url).hostname;
    const consentData = await chrome.storage.session.get(`tier1_${domain}`);
    if (!consentData[`tier1_${domain}`]) return;
  } catch { return; }

  try {
    const ctrl = new AbortController();
    const result = await runFullScan(
      tab, ctrl.signal, () => {}, undefined,
      `auto-${Date.now()}-${tabId}`, 'quick', settings.scanSensitivity,
    );
    await saveToHistory(result);
    if (settings.backendUrl) {
      syncToWebApp(result, settings.backendUrl).catch(() => {});
    }

    if (settings.enableNotifications) {
      const criticals = result.vulnerabilities.filter(v => v.severity === Severity.CRITICAL);
      if (criticals.length > 0) {
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon48.png',
          title: `CyberINTEL-AI — ${criticals.length} CRITICAL finding${criticals.length > 1 ? 's' : ''}`,
          message: `${result.domain}: ${criticals[0].title}`,
          priority: 2,
        });
      }
    }
  } catch { /* non-fatal */ }
});

// ─── Startup / Install ────────────────────────────────────
chrome.runtime.onInstalled.addListener(async () => {
  const data = await chrome.storage.local.get('settings');
  if (!data.settings) await chrome.storage.local.set({ settings: DEFAULT_SETTINGS });
  await chrome.storage.local.remove('modelStatus');
  ensureOffscreen().catch(() => {});
  console.log('[CyberINTEL-AI] Installed/updated');
});

chrome.runtime.onStartup.addListener(() => {
  chrome.storage.local.remove('modelStatus');
  ensureOffscreen().catch(() => {});
});

console.log('[CyberINTEL-AI] Service worker ready');
