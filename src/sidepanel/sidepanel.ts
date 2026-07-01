import './sidepanel.css';
import {
  ScanResult, Vulnerability, Severity, ScanCategory,
  MLPrediction, MonitorEvent, ExtensionMessage, DOMScanResult,
  MLModelStatus,
} from '../types/index';
import { generatePDFReport, exportJSON } from '../utils/report';
import {
  scoreToGrade, countBySeverity, toSubCheckFinding,
} from '../utils/scoring';
import { calculateScore, deductionForFinding, SubCheckFinding } from '../scoring/engine';

const $ = (id: string): HTMLElement => document.getElementById(id)!;
function esc(s: string): string {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Module state ──────────────────────────────────────────
let currentScan:  ScanResult | null      = null;
let currentTab:   chrome.tabs.Tab | null = null;
let mlReady     = false;
let mlLoading   = true;
let isScanning  = false;
let activeScanId: string | null = null;
let mlStatus: MLModelStatus = { xss: false, phishing: false, anomaly: false, any: false, all: false };
let threatScanActive  = false;
let latestThreatScan: ScanResult | null = null;

// Progressive scan state (previous session)
let _liveScanning     = false;
let _scoreAnimFrame: number | null = null;
let _scoreDisplayVal  = 100;

// ── Reveal queue — one-finding-at-a-time system ───────────
const REVEAL_DELAYS = { cinematic: 2200, normal: 1200, fast: 350 } as const;

let _revealQueue: Array<{ finding: Vulnerability; scoreBefore: number; scoreAfter: number }> = [];
let _revealRunning    = false;
let _visualScore      = 100;
let _visualCounts     = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
let _analystFindings: Vulnerability[] = [];
let _allScFindings: SubCheckFinding[] = [];   // accumulates all findings for engine scoring
let _vivaMode         = false;
let _revealSpeed: 'cinematic' | 'normal' | 'fast' = 'normal';
let _pendingFinalScan: ScanResult | null = null;
let _totalRevealed    = 0;
let _gradeProvisional = false;

// ── Cinematic steps ───────────────────────────────────────
const CINEMATIC_STEPS = [
  'TARGET ACQUIRED',
  'INITIALIZING SCAN PROTOCOLS',
  'OPENING TARGET CHANNEL',
  'ANALYZING PAGE STRUCTURE',
  'EXTRACTING HEADERS & METADATA',
  'SCANNING FOR VULNERABILITIES',
  'CROSS-REFERENCING THREAT DATABASE',
  'COMPILING FINDINGS',
  'CLOSING CHANNEL',
  'SCAN COMPLETE — REPORT READY',
];

// ── Stage map for progress indicator ─────────────────────
const STAGE_MAP: Record<string, string> = {
  init: 'dom', dom: 'dom',
  transport: 'headers', headers: 'headers', ssl: 'headers',
  cookies: 'headers', network: 'headers', server: 'headers',
  phishing: 'dom', forms: 'dom', jwt: 'dom', mixed: 'dom', trackers: 'dom',
  ml: 'ml', done: 'ml',
};

// ── Confidence tier inference (for findings not tagged at source) ─
function inferConfidenceTier(v: Vulnerability): 'high' | 'medium' | 'low' {
  if (v.confidence_tier) return v.confidence_tier;

  if (v.detectedBy === 'ml') {
    if (v.category === ScanCategory.ANOMALY) return 'low';
    return (v.confidence ?? 0) >= 0.85 ? 'high' : 'medium';
  }

  switch (v.category as ScanCategory) {
    case ScanCategory.HEADERS:
    case ScanCategory.SSL:
    case ScanCategory.COOKIES:
    case ScanCategory.MIXED_CONTENT:
    case ScanCategory.SERVER_INFO:
    case ScanCategory.SENSITIVE_FILES:
      return 'high';
    case ScanCategory.JWT:
      return (v.severity === Severity.CRITICAL || v.severity === Severity.HIGH)
        ? 'high' : 'medium';
    case ScanCategory.FORMS:
      return v.severity === Severity.CRITICAL ? 'high' : 'medium';
    case ScanCategory.PHISHING:
      return (v.severity === Severity.HIGH || v.severity === Severity.CRITICAL)
        ? 'high' : 'medium';
    case ScanCategory.ANOMALY:
      return 'low';
    case ScanCategory.TRACKERS:
    case ScanCategory.SCRIPTS:
      return 'medium';
    default:
      return v.severity === Severity.CRITICAL ? 'high' : 'medium';
  }
}

function inferObsLabel(v: Vulnerability): 'observed' | 'inferred' {
  if (v.observed_or_inferred) return v.observed_or_inferred;
  return v.detectedBy === 'ml' ? 'inferred' : 'observed';
}

// ── Score ring animation ──────────────────────────────────
function animateScoreRing(target: number, grade: string) {
  if (_scoreAnimFrame !== null) cancelAnimationFrame(_scoreAnimFrame);
  const from      = _scoreDisplayVal;
  const startTime = performance.now();
  const DURATION  = 700;
  const CIRC      = 264;

  function tick(now: number) {
    const t       = Math.min((now - startTime) / DURATION, 1);
    const eased   = 1 - Math.pow(1 - t, 3);
    const current = Math.round(from + (target - from) * eased);
    _scoreDisplayVal = current;

    const ring   = $('score-ring-fill') as unknown as SVGCircleElement;
    const offset = CIRC - (current / 100) * CIRC;
    ring.style.strokeDashoffset = String(offset);

    const g   = scoreToGrade(current);
    const col = g === 'A' || g === 'B'        ? '#30d158'
              : g === 'C'                      ? '#ffcc00'
              : g === 'D' || g === 'E'         ? '#ff8c00' : '#ff3b46';
    ring.style.stroke          = col;
    $('score-value').textContent = String(current);
    ($('score-grade') as HTMLElement).style.color = col;

    if (t < 1) {
      _scoreAnimFrame = requestAnimationFrame(tick);
    } else {
      _scoreAnimFrame  = null;
      _scoreDisplayVal = target;
      if (_gradeProvisional) {
        $('score-grade').textContent = `~${grade}`;
        ($('score-grade') as HTMLElement).classList.add('grade-provisional');
      } else {
        $('score-grade').textContent = `GRADE ${grade}`;
        ($('score-grade') as HTMLElement).classList.remove('grade-provisional');
      }
    }
  }
  _scoreAnimFrame = requestAnimationFrame(tick);
}

function setScore(score: number, grade: string) {
  _scoreDisplayVal = score;
  const CIRC   = 264;
  const offset = CIRC - (score / 100) * CIRC;
  const ring   = $('score-ring-fill') as unknown as SVGCircleElement;
  ring.style.strokeDashoffset = String(offset);
  const c = grade === 'A' || grade === 'B'        ? '#30d158'
           : grade === 'C'                          ? '#ffcc00'
           : grade === 'D' || grade === 'E'         ? '#ff8c00' : '#ff3b46';
  ring.style.stroke             = c;
  $('score-value').textContent  = String(score);
  if (_gradeProvisional) {
    $('score-grade').textContent = `~${grade}`;
    ($('score-grade') as HTMLElement).classList.add('grade-provisional');
  } else {
    $('score-grade').textContent = `GRADE ${grade}`;
    ($('score-grade') as HTMLElement).classList.remove('grade-provisional');
  }
  ($('score-grade') as HTMLElement).style.color = c;
}

function setSeverityCounts(counts: { critical:number; high:number; medium:number; low:number; info:number }) {
  $('cnt-crit').textContent = String(counts.critical);
  $('cnt-high').textContent = String(counts.high);
  $('cnt-med').textContent  = String(counts.medium);
  $('cnt-low').textContent  = String(counts.low);
  $('cnt-info').textContent = String(counts.info);
}

function updateTargetStats(scan: ScanResult) {
  $('stat-scripts').textContent = scan.dom ? String(scan.dom.scripts.length) : '—';
  $('stat-forms').textContent   = scan.dom ? String(scan.dom.forms.length)   : '—';
  $('stat-cookies').textContent = String(scan.cookies.length);
}

function setStage(id: string, state: 'active' | 'done') {
  const el = $(`stage-${id}`);
  el.classList.remove('active', 'done');
  el.classList.add(state);
}

function showProgress(visible: boolean) {
  ($('progress-zone') as HTMLElement).style.display = visible ? 'block' : 'none';
}

function setScanningState(scanning: boolean) {
  isScanning = scanning;
  const btnQ = $('btn-quick')  as HTMLButtonElement;
  const btnF = $('btn-full')   as HTMLButtonElement;
  const btnS = $('btn-stop')   as HTMLButtonElement;
  btnQ.disabled = scanning;
  btnF.disabled = scanning;
  btnS.style.display = scanning ? 'inline-flex' : 'none';
  const pulse = $('target-pulse');
  if (scanning) pulse.classList.add('scanning');
  else          pulse.classList.remove('scanning');
}

// ── Timeline log ──────────────────────────────────────────
function addTimelineEntry(message: string) {
  const tl = document.getElementById('scan-timeline');
  if (!tl) return;
  const entry = document.createElement('div');
  entry.className = 'tl-entry';
  entry.textContent = `▸ ${message}`;
  tl.appendChild(entry);
  const all = tl.querySelectorAll('.tl-entry');
  if (all.length > 5) all[0].remove();
}

// ── Progressive scan init ─────────────────────────────────
function initLiveScan() {
  _liveScanning     = true;
  _scoreDisplayVal  = 100;

  // Reset reveal queue state
  _revealQueue      = [];
  _revealRunning    = false;
  _visualScore      = 100;
  _visualCounts     = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  _analystFindings  = [];
  _allScFindings    = [];
  _pendingFinalScan = null;
  _totalRevealed    = 0;
  _gradeProvisional = true;

  // Score ring: 100 / provisional grade
  setScore(100, 'A');
  setSeverityCounts({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });

  // Findings pane: waiting state
  $('findings-list').innerHTML =
    '<div class="scan-wait-state"><div class="swp-pulse"></div><span>Analyzing target&nbsp;&mdash;&nbsp;findings appear as discovered</span></div>';

  // Hide spotlight
  const spotlight = document.getElementById('finding-spotlight');
  if (spotlight) {
    spotlight.style.display = 'none';
    spotlight.classList.remove('spotlight-active');
  }

  // Hide analyst section
  const analyst = document.getElementById('analyst-review-section');
  if (analyst) analyst.style.display = 'none';

  // Viva mode banner visibility
  const vivaBanner = document.getElementById('viva-mode-banner');
  if (vivaBanner) vivaBanner.style.display = _vivaMode ? 'block' : 'none';

  // Disable exports
  ($('btn-pdf')  as HTMLButtonElement).disabled = true;
  ($('btn-json') as HTMLButtonElement).disabled = true;

  // Reset progress bar
  $('progress-phase').textContent = 'Initializing...';
  ($('progress-bar-fill') as HTMLElement).style.width = '0%';
  $('progress-pct').textContent = '0%';

  // Clear timeline
  const tl = document.getElementById('scan-timeline');
  if (tl) tl.innerHTML = '';

  // Clear discovery tab stubs
  ['scripts','forms','links','cookies'].forEach(d => {
    const el = document.getElementById(`disc-${d}`);
    if (el) el.innerHTML = '<div class="empty-state">Scanning&hellip;</div>';
  });
}

// ── Spotlight card HTML (focused single-finding view) ─────
function buildSpotlightHTML(v: Vulnerability): string {
  const tier    = inferConfidenceTier(v);
  const obs     = inferObsLabel(v);
  const aiBadge = v.detectedBy === 'ml' ? '<span class="ai-badge">AI</span>' : '';
  const confPct = v.confidence != null
    ? `<span class="spotlight-conf">&nbsp;&#183;&nbsp;${Math.round(v.confidence * 100)}% confidence</span>`
    : '';

  return `
    <div class="spotlight-sev-row">
      <span class="sev-tag sev-${v.severity.toLowerCase()}">${v.severity}</span>
      <span class="tier-badge tier-${tier}">${tier.toUpperCase()} CONFIDENCE</span>
      <span class="obs-badge obs-${obs}">${obs}</span>
      ${aiBadge}
    </div>
    <div class="spotlight-title">${esc(v.title)}</div>
    <div class="spotlight-meta">
      <span class="spotlight-cat">${esc(v.category)}</span>
      <span class="meta-sep">&#183;</span>
      <span class="spotlight-loc">${esc(v.location)}</span>
      ${confPct}
    </div>
    <div class="spotlight-cause"><strong>Why it matters:</strong> ${esc(v.description)}</div>
    ${v.evidence
      ? `<div class="spotlight-evidence"><span class="ev-label">Evidence:</span><code>${esc(v.evidence)}</code></div>`
      : ''}
    <div class="spotlight-fix"><span class="fix-label">&#10003; Fix:</span> ${esc(v.remediation)}</div>`;
}

// ── Finding card HTML (promoted list entries + history replay) ─
function buildFindingCardHTML(v: Vulnerability): string {
  const tier      = inferConfidenceTier(v);
  const confBadge = v.detectedBy === 'ml' && v.confidence != null
    ? `<span class="conf-badge">${Math.round(v.confidence * 100)}%</span>` : '';
  const aiBadge   = v.detectedBy === 'ml' ? '<span class="ai-badge">AI</span>' : '';
  const tierDot   = `<span class="tier-dot tier-dot-${tier}" title="${tier} confidence"></span>`;

  return `
    <div class="finding-header">
      <span class="sev-tag sev-${v.severity.toLowerCase()}">${v.severity}</span>
      <span class="finding-title">${esc(v.title)}</span>
      ${tierDot}${aiBadge}${confBadge}
    </div>
    <div class="finding-meta">
      <span class="finding-cat">${esc(v.category)}</span>
      <span class="meta-sep">&#183;</span>
      <span class="finding-loc">${esc(v.location)}</span>
    </div>
    <div class="finding-desc">${esc(v.description)}</div>
    ${v.evidence ? `<div class="finding-evidence"><code>${esc(v.evidence)}</code></div>` : ''}
    <div class="finding-fix">&#10003; ${esc(v.remediation)}</div>`;
}

// ── Findings — full re-render (history replay / aborted) ──
function renderFindings(vulns: Vulnerability[]) {
  const list = $('findings-list');
  if (vulns.length === 0) {
    list.innerHTML = '<div class="empty-state">No vulnerabilities detected</div>';
    return;
  }
  const order: Record<string, number> = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4 };
  const sorted = [...vulns].sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
  list.innerHTML = sorted.map((v, i) => `
    <div class="finding-card" style="animation-delay:${Math.min(i * 25, 300)}ms">
      ${buildFindingCardHTML(v)}
    </div>`).join('');
}

// ── Analyst review panel ──────────────────────────────────
function renderAnalystReview() {
  const section  = document.getElementById('analyst-review-section') as HTMLElement | null;
  const listEl   = document.getElementById('analyst-review-list')   as HTMLElement | null;
  const countEl  = document.getElementById('analyst-count')          as HTMLElement | null;
  if (!section || !listEl || !countEl) return;

  section.style.display = 'block';
  countEl.textContent   = String(_analystFindings.length);
  listEl.innerHTML      = _analystFindings.map(f => `
    <div class="finding-card analyst-card">
      ${buildFindingCardHTML(f)}
    </div>`).join('');
}

// ── Promote a finding from spotlight into the revealed list ─
function promoteToRevealedList(f: Vulnerability) {
  const list = $('findings-list');
  const card = document.createElement('div');
  card.className = 'finding-card finding-promoted';
  card.innerHTML = buildFindingCardHTML(f);
  list.appendChild(card);
}

// ── Enqueue findings into the one-at-a-time reveal queue ──
function enqueueFindings(findings: Vulnerability[]) {
  if (!findings.length) return;

  for (const f of findings) {
    const tier = inferConfidenceTier(f);

    if (_vivaMode && tier !== 'high') {
      _analystFindings.push(f);
      continue;
    }

    // Convert to engine format and accumulate
    const scf = toSubCheckFinding(f);
    _allScFindings.push(scf);

    // In strict (Viva) mode, non-critical/high findings don't deduct
    const sevLC = f.severity.toLowerCase() as string;
    const deduction = (_vivaMode && sevLC !== 'critical' && sevLC !== 'high')
      ? 0
      : deductionForFinding(scf, _allScFindings);

    const scoreBefore = _visualScore;
    _visualScore      = Math.max(0, _visualScore - deduction);
    _revealQueue.push({ finding: f, scoreBefore, scoreAfter: _visualScore });
  }

  if (_vivaMode && _analystFindings.length > 0) renderAnalystReview();
  if (!_revealRunning) startRevealLoop();
}

// ── Reveal loop: shows one finding at a time ──────────────
async function startRevealLoop() {
  if (_revealRunning) return;
  _revealRunning = true;

  const spotlightEl = document.getElementById('finding-spotlight') as HTMLElement | null;
  const spotCardEl  = document.getElementById('spotlight-card')    as HTMLElement | null;
  const queueInfoEl = document.getElementById('spotlight-queue-info') as HTMLElement | null;

  while (_revealQueue.length > 0) {
    const item = _revealQueue.shift()!;
    _totalRevealed++;

    // Remove waiting placeholder on first finding
    const ph = $('findings-list').querySelector('.scan-wait-state, .empty-state, .sp-scanning-msg');
    if (ph) ph.remove();

    // Show spotlight card
    if (spotCardEl) spotCardEl.innerHTML = buildSpotlightHTML(item.finding);
    if (queueInfoEl) {
      const pending = _revealQueue.length;
      queueInfoEl.textContent = pending > 0
        ? `Finding ${_totalRevealed} · ${pending} more queued`
        : `Finding ${_totalRevealed} · Last finding`;
    }
    if (spotlightEl) {
      spotlightEl.style.display = 'block';
      // Small tick to allow display:block to apply before adding the class
      await new Promise<void>(r => setTimeout(r, 30));
      spotlightEl.classList.add('spotlight-active');
    }

    // Animate score ring for this finding
    animateScoreRing(item.scoreAfter, scoreToGrade(item.scoreAfter));

    // Update severity counts
    switch (item.finding.severity) {
      case Severity.CRITICAL: _visualCounts.critical++; break;
      case Severity.HIGH:     _visualCounts.high++;     break;
      case Severity.MEDIUM:   _visualCounts.medium++;   break;
      case Severity.LOW:      _visualCounts.low++;      break;
      case Severity.INFO:     _visualCounts.info++;     break;
    }
    setSeverityCounts(_visualCounts);

    // Hold for configured reveal delay
    await new Promise<void>(r => setTimeout(r, REVEAL_DELAYS[_revealSpeed]));

    // Promote to revealed list
    promoteToRevealedList(item.finding);

    // Fade spotlight out, then hide
    if (spotlightEl) spotlightEl.classList.remove('spotlight-active');
    await new Promise<void>(r => setTimeout(r, 220));
    if (spotlightEl && _revealQueue.length === 0) spotlightEl.style.display = 'none';
    await new Promise<void>(r => setTimeout(r, 80));
  }

  _revealRunning = false;

  // Finalize if scan completed while queue was draining
  if (_pendingFinalScan) finalizeScanDisplay();
}

// ── Finalize display after reveal queue drains ────────────
function finalizeScanDisplay() {
  const scan = _pendingFinalScan;
  if (!scan) return;
  _pendingFinalScan = null;
  _gradeProvisional = false;
  currentScan       = scan;

  // Use the canonical engine to compute the final authoritative score.
  // calculateScore() applies per-subcheck caps and deduplication — the result
  // may differ slightly from _visualScore (which was approximate during reveal)
  // but this snaps to the correct value without double-counting findings.
  const bd = calculateScore(_allScFindings, _vivaMode);
  const displayScore = bd.finalScore;
  const displayGrade = bd.grade;
  animateScoreRing(displayScore, displayGrade);
  setSeverityCounts(_visualCounts);
  updateTargetStats(scan);

  renderDiscovery(scan);
  renderML(scan.mlPredictions);
  if (scan.mlPredictions.length > 0) updateMLDotsCompleted(scan.mlPredictions);

  if (scan.status === 'complete') updateExportInfo(scan);

  // Aborted: show exact partial findings
  if (scan.status === 'aborted') renderFindings(scan.vulnerabilities);

  const n = scan.vulnerabilities.length;
  $('scan-status').textContent = `${n} finding${n !== 1 ? 's' : ''}`;
  $('scan-time').textContent   = `${new Date(scan.scannedAt).toLocaleTimeString()} — ${scan.scanDurationMs}ms`;

  if (_analystFindings.length > 0) renderAnalystReview();
}

// ── Auth: Tier 1 ─────────────────────────────────────────
async function requestTier1Auth(domain: string): Promise<boolean> {
  const key = `tier1_${domain}`;
  try {
    const stored = await chrome.storage.session.get(key);
    if (stored[key] === true) return true;
  } catch { /* */ }

  return new Promise(resolve => {
    $('tier1-domain').textContent = domain;
    const modal   = $('modal-tier1') as HTMLElement;
    modal.style.display = 'flex';

    const allow  = $('btn-tier1-allow')  as HTMLButtonElement;
    const cancel = $('btn-tier1-cancel') as HTMLButtonElement;
    const cleanup = () => { modal.style.display = 'none'; };

    allow.onclick = async () => {
      cleanup();
      try { await chrome.storage.session.set({ [key]: true }); } catch { /* */ }
      resolve(true);
    };
    cancel.onclick = () => { cleanup(); resolve(false); };
  });
}

// ── ML model status dots ──────────────────────────────────
function updateMLDots() {
  const models = ['xss', 'phishing', 'anomaly'] as const;
  for (const m of models) {
    const dot   = $(`dot-${m}`);
    const state = $(`state-${m}`);
    if (mlLoading) {
      dot.className        = 'ml-dot';
      dot.style.background = 'var(--med)';
      state.textContent    = 'Loading...';
      (state as HTMLElement).style.color = '';
    } else if (mlStatus[m]) {
      dot.className        = 'ml-dot loaded';
      dot.style.background = '';
      state.textContent    = 'Ready';
      (state as HTMLElement).style.color = '#30d158';
    } else {
      dot.className        = 'ml-dot failed';
      dot.style.background = '';
      state.textContent    = 'Not loaded';
      (state as HTMLElement).style.color = '#ff8c00';
    }
  }
  mlReady = mlStatus.any;
}

function updateMLDotsCompleted(preds: MLPrediction[]) {
  mlLoading = false;
  const models = ['xss', 'phishing', 'anomaly'] as const;
  for (const m of models) {
    const dot   = $(`dot-${m}`);
    const state = $(`state-${m}`);
    const pred  = preds.find(p => p.modelName === m);
    if (pred) {
      dot.className     = 'ml-dot loaded';
      dot.style.background = '';
      state.textContent = 'Completed';
      (state as HTMLElement).style.color = '#30d158';
    } else if (mlStatus[m]) {
      state.textContent = 'Ready (not run)';
    }
  }
}

// ── Progress handler ──────────────────────────────────────
function handleProgress(stage: string, pct: number, message: string, payload?: any) {
  $('progress-phase').textContent = message;

  // Stage indicator dots
  const stageId    = STAGE_MAP[stage] ?? stage;
  const stageOrder = ['dom', 'headers', 'ml'];
  const idx        = stageOrder.indexOf(stageId);
  stageOrder.forEach((s, i) => {
    const el = $(`stage-${s}`);
    if (!el) return;
    el.classList.remove('active', 'done');
    if (i < idx)        el.classList.add('done');
    else if (i === idx) el.classList.add('active');
  });

  // Progress bar
  const fill  = $('progress-bar-fill') as HTMLElement;
  const pctEl = $('progress-pct')      as HTMLElement;
  if (fill)  fill.style.width    = `${pct}%`;
  if (pctEl) pctEl.textContent   = `${pct}%`;

  // Enqueue incoming findings into the reveal queue
  if (_liveScanning && Array.isArray(payload?.addedFindings) && payload.addedFindings.length > 0) {
    enqueueFindings(payload.addedFindings as Vulnerability[]);
  }

  // Timeline log
  if (_liveScanning && message && stage !== 'init') {
    addTimelineEntry(message);
  }
}

// ── Tab navigation ────────────────────────────────────────
document.querySelectorAll('.sp-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.sp-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.pane').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    $(`pane-${tab.getAttribute('data-pane')}`).classList.add('active');
  });
});

document.querySelectorAll('.disc-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.disc-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.disc-pane').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    $(`disc-${tab.getAttribute('data-disc')}`).classList.add('active');
  });
});

// ── Discovery panel ───────────────────────────────────────
function renderDiscovery(scan: ScanResult) {
  const dom = scan.dom;
  if (!dom) {
    ['scripts','forms','links','cookies'].forEach(d => {
      $(`disc-${d}`).innerHTML = '<div class="empty-state">DOM data unavailable</div>';
    });
    return;
  }

  $('disc-scripts').innerHTML = dom.scripts.length === 0
    ? '<div class="empty-state">No scripts found</div>'
    : `<table class="disc-table"><thead><tr>
        <th>Type</th><th>Source / Snippet</th><th>Status</th>
      </tr></thead><tbody>
      ${dom.scripts.map(s => `
        <tr class="${s.isSuspicious ? 'row-warn' : ''}">
          <td><span class="disc-badge ${s.isInline ? 'badge-inline' : 'badge-ext'}">${s.isInline ? 'Inline' : 'External'}</span></td>
          <td class="disc-src">${esc((s.src ?? s.snippet ?? '').slice(0, 80))}</td>
          <td>${s.isSuspicious
            ? `<span class="disc-bad">${esc(s.suspicionReason ?? 'Suspicious')}</span>`
            : '<span class="disc-ok">OK</span>'}</td>
        </tr>`).join('')}
      </tbody></table>`;

  $('disc-forms').innerHTML = dom.forms.length === 0
    ? '<div class="empty-state">No forms found</div>'
    : `<table class="disc-table"><thead><tr>
        <th>Action</th><th>Method</th><th>Password</th><th>CSRF</th><th>HTTP?</th>
      </tr></thead><tbody>
      ${dom.forms.map(f => `
        <tr class="${f.submitsOverHTTP && f.hasPasswordField ? 'row-crit' : f.submitsOverHTTP ? 'row-warn' : ''}">
          <td class="disc-src">${esc(f.action || '(self)')}</td>
          <td>${esc(f.method)}</td>
          <td>${f.hasPasswordField ? '<span class="disc-bad">Yes</span>' : '—'}</td>
          <td>${f.hasCsrfToken ? '<span class="disc-ok">Yes</span>' : '<span class="disc-bad">No</span>'}</td>
          <td>${f.submitsOverHTTP ? '<span class="disc-crit">YES</span>' : '—'}</td>
        </tr>`).join('')}
      </tbody></table>`;

  const notable = dom.links.filter(l => l.isSuspicious || l.isExternal);
  $('disc-links').innerHTML = notable.length === 0
    ? '<div class="empty-state">No external or suspicious links found</div>'
    : `<table class="disc-table"><thead><tr>
        <th>URL</th><th>External</th><th>Suspicious</th>
      </tr></thead><tbody>
      ${notable.map(l => `
        <tr class="${l.isSuspicious ? 'row-warn' : ''}">
          <td class="disc-src">${esc(l.href.length > 70 ? l.href.slice(0,70)+'…' : l.href)}</td>
          <td>${l.isExternal ? 'Yes' : '—'}</td>
          <td>${l.isSuspicious ? '<span class="disc-bad">Yes</span>' : '—'}</td>
        </tr>`).join('')}
      </tbody></table>`;

  $('disc-cookies').innerHTML = scan.cookies.length === 0
    ? '<div class="empty-state">No cookies found</div>'
    : `<table class="disc-table"><thead><tr>
        <th>Name</th><th>HttpOnly</th><th>Secure</th><th>SameSite</th>
      </tr></thead><tbody>
      ${scan.cookies.map(c => `
        <tr class="${c.issues.length > 0 ? 'row-warn' : ''}">
          <td class="disc-src">${esc(c.name)}</td>
          <td>${c.httpOnly ? '<span class="disc-ok">Yes</span>' : '<span class="disc-bad">No</span>'}</td>
          <td>${c.secure   ? '<span class="disc-ok">Yes</span>' : '<span class="disc-bad">No</span>'}</td>
          <td>${esc(c.sameSite ?? 'None')}</td>
        </tr>`).join('')}
      </tbody></table>`;
}

// ── AI/ML panel ───────────────────────────────────────────
function renderML(preds: MLPrediction[]) {
  const container = $('ml-results');
  if (preds.length === 0) {
    container.innerHTML = '<div class="empty-state">Run a Full Audit to see AI analysis</div>';
    return;
  }
  const labels: Record<string, string> = {
    xss: 'XSS Detection', phishing: 'Phishing Detection', anomaly: 'Anomaly Detection',
  };
  container.innerHTML = preds.map(p => `
    <div class="ml-card glass-card">
      <div class="ml-card-head">
        <span class="ml-label">${labels[p.modelName] ?? p.modelName}</span>
        <span class="ml-verdict ${p.isMalicious ? 'verdict-mal' : 'verdict-ok'}">
          ${p.isMalicious ? 'THREAT DETECTED' : 'CLEAR'}
        </span>
      </div>
      <div class="ml-bar-wrap">
        <div class="ml-bar">
          <div class="ml-fill ${p.isMalicious ? 'fill-mal' : 'fill-ok'}"
               style="width:${(p.confidence * 100).toFixed(0)}%"></div>
        </div>
        <span class="ml-pct">${(p.confidence * 100).toFixed(1)}%</span>
      </div>
      ${p.analysisContext ? `<div class="ml-context">${esc(p.analysisContext)}</div>` : ''}
      ${p.findingsSummary ? `<div class="ml-summary ${p.isMalicious ? 'ml-summary-bad' : 'ml-summary-ok'}">${esc(p.findingsSummary)}</div>` : ''}
      <div class="ml-features">
        ${Object.entries(p.features).map(([k, v]) => `
          <div class="ml-feat">
            <span class="ml-feat-k">${esc(k.replace(/_/g,' '))}</span>
            <span class="ml-feat-v">${typeof v === 'number'
              ? (Number.isInteger(v) ? v : (v as number).toFixed(4))
              : esc(String(v))}</span>
          </div>`).join('')}
      </div>
      <div class="ml-timing">${p.inferenceTimeMs.toFixed(1)} ms inference</div>
    </div>`).join('');
}

// ── Monitor stream ────────────────────────────────────────
function addMonitorEvent(evt: MonitorEvent) {
  const list  = $('monitor-list');
  const empty = list.querySelector('.empty-state');
  if (empty) empty.remove();
  const time = new Date(evt.timestamp).toLocaleTimeString('en-US', {
    hour12: false, hour:'2-digit', minute:'2-digit', second:'2-digit',
  });
  const el = document.createElement('div');
  el.className = 'monitor-evt';
  el.innerHTML = `
    <span class="evt-time">${time}</span>
    <span class="evt-dot sev-${evt.severity.toLowerCase()}"></span>
    <span class="evt-desc" title="${esc(evt.description)}">${esc(evt.description)}</span>`;
  list.insertBefore(el, list.firstChild);
  const all = list.querySelectorAll('.monitor-evt');
  if (all.length > 120) all[all.length - 1].remove();
}

function updateExportInfo(scan: ScanResult) {
  $('export-summary').textContent =
    `${scan.vulnerabilities.length} finding${scan.vulnerabilities.length !== 1 ? 's' : ''} on ${scan.domain}. Score: ${scan.securityScore}/100 (Grade ${scan.grade}).`;
  ($('btn-pdf')  as HTMLButtonElement).disabled = false;
  ($('btn-json') as HTMLButtonElement).disabled = false;
}

function showBanner(text: string) {
  const list = $('findings-list');
  list.querySelectorAll('.partial-banner').forEach(b => b.remove());
  const el = document.createElement('div');
  el.className = 'partial-banner';
  el.textContent = text;
  list.insertBefore(el, list.firstChild);
}

// ── Scan history ──────────────────────────────────────────
async function renderHistory() {
  const list = $('history-list');
  try {
    const { scanHistory = [] } = await chrome.storage.local.get('scanHistory') as { scanHistory: ScanResult[] };
    if (scanHistory.length === 0) {
      list.innerHTML = '<div class="empty-state">No scan history yet</div>';
      return;
    }
    list.innerHTML = scanHistory.map((s, i) => {
      const dateStr = new Date(s.scannedAt).toLocaleString();
      const gc = s.grade === 'A' || s.grade === 'B'        ? '#30d158'
               : s.grade === 'C'                            ? '#ffcc00'
               : s.grade === 'D' || s.grade === 'E'         ? '#ff8c00' : '#ff3b46';
      const abortedTag = s.status === 'aborted'
        ? '<span style="color:var(--med);font-size:9px">PARTIAL</span>' : '';
      return `
        <div class="history-item" data-idx="${i}">
          <div class="history-main">
            <span class="history-domain">${esc(s.domain)}</span>
            ${abortedTag}
            <span class="history-grade" style="color:${gc}">${s.grade}</span>
            <span class="history-score">${s.securityScore}</span>
          </div>
          <div class="history-meta">
            <span class="history-counts">
              ${s.counts.critical > 0 ? `<span class="hc-crit">${s.counts.critical}C</span>` : ''}
              ${s.counts.high     > 0 ? `<span class="hc-high">${s.counts.high}H</span>` : ''}
              ${s.counts.medium   > 0 ? `<span class="hc-med">${s.counts.medium}M</span>` : ''}
            </span>
            <span class="history-time">${esc(dateStr)}</span>
          </div>
        </div>`;
    }).join('');

    list.querySelectorAll('.history-item').forEach(el => {
      (el as HTMLElement).addEventListener('click', () => {
        const idx = parseInt((el as HTMLElement).dataset.idx ?? '0', 10);
        replayScan(scanHistory[idx]);
      });
    });
  } catch {
    list.innerHTML = '<div class="empty-state">Failed to load history</div>';
  }
}

function replayScan(scan: ScanResult) {
  displayScan(scan);
  showBanner(`Replayed scan — ${new Date(scan.scannedAt).toLocaleString()}`);
  document.querySelectorAll('.sp-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.pane').forEach(p => p.classList.remove('active'));
  document.querySelector('[data-pane="findings"]')?.classList.add('active');
  $('pane-findings').classList.add('active');
}

// ── Full render — history replay and init restore ─────────
function displayScan(scan: ScanResult) {
  currentScan       = scan;
  _gradeProvisional = false;
  setScore(scan.securityScore, scan.grade);
  setSeverityCounts(scan.counts);
  updateTargetStats(scan);
  renderFindings(scan.vulnerabilities);
  renderDiscovery(scan);
  renderML(scan.mlPredictions);
  updateExportInfo(scan);
  if (scan.mlPredictions.length > 0) updateMLDotsCompleted(scan.mlPredictions);
  $('scan-status').textContent =
    `${scan.vulnerabilities.length} finding${scan.vulnerabilities.length !== 1 ? 's' : ''}`;
  $('scan-time').textContent =
    `${new Date(scan.scannedAt).toLocaleTimeString()} — ${scan.scanDurationMs}ms`;
}

// ── Live-scan completion ──────────────────────────────────
// If the reveal queue is still draining, register the final scan for deferred finalization.
// Otherwise finalize immediately.
function displayScanFinal(scan: ScanResult) {
  currentScan   = scan;
  _liveScanning = false;

  _pendingFinalScan = scan;
  if (!_revealRunning && _revealQueue.length === 0) {
    finalizeScanDisplay();
  }
  // else: finalizeScanDisplay() will be called by startRevealLoop() when queue empties
}

// ── Cinematic view helpers ────────────────────────────────
function showNormalContent(visible: boolean) {
  const ids = ['progress-zone', 'sev-strip'] as const;
  for (const id of ids) {
    ($(id) as HTMLElement).style.display = visible ? '' : 'none';
  }
  document.querySelectorAll<HTMLElement>(
    '.sp-header, .target-card, .control-row, .auth-section, .sp-tabs, .pane',
  ).forEach(el => { el.style.display = visible ? '' : 'none'; });
}

function showCinematicView(domain: string) {
  showNormalContent(false);
  ($('threat-report-view') as HTMLElement).style.display = 'none';
  const cv = $('cinematic-view') as HTMLElement;
  cv.style.display = 'flex';
  $('cin-domain').textContent = domain;
  $('cin-channel-label').textContent = 'STANDBY';
  ($('cin-prog-fill') as HTMLElement).style.width = '0%';
  renderCinematicSteps(-1);
  $('cin-live').textContent = 'STANDBY';
}

function renderCinematicSteps(activeIdx: number) {
  $('cin-steps').innerHTML = CINEMATIC_STEPS.map((label, i) => {
    const done    = i < activeIdx;
    const current = i === activeIdx;
    const cls = done ? 'cin-step cin-step-done'
              : current ? 'cin-step cin-step-active'
              : 'cin-step cin-step-pending';
    const prefix = done ? '<span class="cin-check">&#10003;</span> ' : '';
    const cursor = current ? '<span class="cin-cursor">_</span>' : '';
    return `<div class="${cls}">${prefix}${label}${cursor}</div>`;
  }).join('');
}

function updateCinematicStep(
  step: number, channelNum: number, totalChannels: number, path: string,
) {
  renderCinematicSteps(step);
  if (path) {
    $('cin-channel-label').textContent =
      `SCANNING: ${path}  [ ${channelNum} OF ${totalChannels} ]`;
    const pct = totalChannels > 0
      ? Math.round(((channelNum - 1 + (step - 2) / 7) / totalChannels) * 100)
      : 0;
    ($('cin-prog-fill') as HTMLElement).style.width = `${Math.max(0, Math.min(pct, 99))}%`;
  } else if (step === 9) {
    $('cin-channel-label').textContent = 'ALL CHANNELS COMPLETE';
    ($('cin-prog-fill') as HTMLElement).style.width = '100%';
  }
  $('cin-live').textContent = CINEMATIC_STEPS[step] ?? 'PROCESSING';
}

// ── Threat report view ────────────────────────────────────
function showThreatReport(scan: ScanResult) {
  ($('cinematic-view') as HTMLElement).style.display = 'none';

  $('rpt-domain').textContent    = scan.domain;
  $('rpt-timestamp').textContent = new Date(scan.scannedAt).toLocaleString();

  const { critical, high, medium, low, info } = scan.counts;
  $('rpt-counts').innerHTML = [
    critical > 0 ? `<span class="rpt-cnt rpt-crit">${critical} CRITICAL</span>` : '',
    high     > 0 ? `<span class="rpt-cnt rpt-high">${high} HIGH</span>` : '',
    medium   > 0 ? `<span class="rpt-cnt rpt-med">${medium} MEDIUM</span>` : '',
    low      > 0 ? `<span class="rpt-cnt rpt-low">${low} LOW</span>` : '',
    info     > 0 ? `<span class="rpt-cnt rpt-info">${info} INFO</span>` : '',
  ].filter(Boolean).join('');

  const order: Record<string, number> = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4 };
  const sorted = [...scan.vulnerabilities].sort(
    (a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5)
  );

  const container = $('rpt-findings');
  container.innerHTML = '';

  if (sorted.length === 0) {
    container.innerHTML = '<div class="rpt-empty">No findings detected on scanned paths.</div>';
  } else {
    sorted.forEach((v, i) => {
      const card = document.createElement('div');
      card.className = `rpt-card rpt-card-${v.severity.toLowerCase()}`;
      card.style.animationDelay = `${Math.min(i * 70, 500)}ms`;
      const icon = v.severity === 'CRITICAL' ? '🔴'
                 : v.severity === 'HIGH'     ? '🟠'
                 : v.severity === 'MEDIUM'   ? '🟡'
                 : v.severity === 'LOW'      ? '🟢' : '⚪';
      card.innerHTML = `
        <div class="rpt-card-stripe"></div>
        <div class="rpt-card-body">
          <div class="rpt-card-top">
            <span class="rpt-sev-badge rpt-sev-${v.severity.toLowerCase()}">${icon} ${v.severity}</span>
            <span class="rpt-card-title">${esc(v.title)}</span>
          </div>
          <div class="rpt-card-url">${esc(v.location)}</div>
          <div class="rpt-card-desc">${esc(v.description)}</div>
          <button class="rpt-view-fix-btn">&#9658; VIEW FIX</button>
          <div class="rpt-fix-body" style="display:none">${esc(v.remediation)}</div>
        </div>`;
      card.querySelector('.rpt-view-fix-btn')?.addEventListener('click', e => {
        const btn   = e.currentTarget as HTMLElement;
        const fixEl = card.querySelector('.rpt-fix-body') as HTMLElement;
        const open  = fixEl.style.display !== 'none';
        fixEl.style.display = open ? 'none' : 'block';
        btn.textContent     = open ? '▶ VIEW FIX' : '▼ HIDE FIX';
      });
      container.appendChild(card);
    });
  }

  ($('threat-report-view') as HTMLElement).style.display = 'block';
  latestThreatScan = scan;
}

function resetToNormal() {
  ($('cinematic-view') as HTMLElement).style.display    = 'none';
  ($('threat-report-view') as HTMLElement).style.display = 'none';
  showNormalContent(true);
  threatScanActive = false;
}

// ── Threat scan runner ────────────────────────────────────
async function startThreatScan() {
  if (!currentTab?.id || isScanning || threatScanActive) return;

  const domain = currentTab.url
    ? (() => { try { return new URL(currentTab.url!).hostname; } catch { return currentTab.url!; } })()
    : 'this website';

  const tier1Granted = await requestTier1Auth(domain);
  if (!tier1Granted) {
    $('scan-status').textContent = 'Threat scan cancelled.';
    return;
  }

  threatScanActive = true;
  isScanning       = true;
  ($('btn-quick')  as HTMLButtonElement).disabled = true;
  ($('btn-full')   as HTMLButtonElement).disabled = true;
  ($('btn-threat') as HTMLButtonElement).disabled = true;

  showCinematicView(domain);

  try {
    const resp = await chrome.runtime.sendMessage({
      type: 'SCAN_REQUEST',
      tabId: currentTab.id,
      payload: { mode: 'threat' },
    } as ExtensionMessage);

    if (resp?.payload) {
      showThreatReport(resp.payload as ScanResult);
    } else {
      resetToNormal();
      $('scan-status').textContent = `Error: ${resp?.error ?? 'No response'}`;
    }
  } catch (err) {
    resetToNormal();
    $('scan-status').textContent = `Threat scan error: ${String(err)}`;
  } finally {
    isScanning       = false;
    threatScanActive = false;
    ($('btn-quick')  as HTMLButtonElement).disabled = false;
    ($('btn-full')   as HTMLButtonElement).disabled = false;
    ($('btn-threat') as HTMLButtonElement).disabled = false;
  }
}

// ── Scan runner ───────────────────────────────────────────
async function startScan(mode: 'quick' | 'full') {
  if (!currentTab?.id || isScanning) return;

  const domain = currentTab.url
    ? (() => { try { return new URL(currentTab.url!).hostname; } catch { return currentTab.url!; } })()
    : 'this website';

  const tier1Granted = await requestTier1Auth(domain);
  if (!tier1Granted) {
    $('scan-status').textContent = 'Scan cancelled. No requests were made.';
    return;
  }

  setScanningState(true);
  showProgress(true);
  ['dom','headers','ml'].forEach(s => $(`stage-${s}`)?.classList.remove('active', 'done'));
  initLiveScan();

  const authToken = ($('auth-token-input') as HTMLInputElement | null)?.value.trim() || undefined;
  const _delay    = (ms: number) => new Promise<void>(r => setTimeout(r, ms));

  try {
    const resp = await chrome.runtime.sendMessage({
      type: 'SCAN_REQUEST',
      tabId: currentTab.id,
      payload: { authToken, mode },
    } as ExtensionMessage);

    if (!resp?.payload) {
      $('scan-status').textContent = `Error: ${resp?.error ?? 'No response from scanner'}`;
      handleProgress('dom', 0, 'Scan failed');
      return;
    }

    const scan = resp.payload as ScanResult;

    if (scan.status === 'aborted') {
      displayScanFinal(scan);
      showBanner('Scan was stopped — showing partial results');
      handleProgress('done', 100, 'Scan stopped');
      await _delay(600);
      return;
    }

    displayScanFinal(scan);
    const n = scan.vulnerabilities.length;
    handleProgress('done', 100, `Scan complete — ${n} finding${n !== 1 ? 's' : ''} found`);
    addTimelineEntry('Report complete. Finalizing…');

    await _delay(1400);

  } catch (err) {
    $('scan-status').textContent = `Scan error: ${String(err)}`;
    handleProgress('dom', 0, 'Scan failed');
  } finally {
    setScanningState(false);
    showProgress(false);
    _liveScanning = false;
    activeScanId  = null;
    if (authToken) ($('auth-token-input') as HTMLInputElement).value = '';
  }
}

// ── Message listener ──────────────────────────────────────
chrome.runtime.onMessage.addListener((msg: ExtensionMessage) => {
  if (msg.type === 'MONITOR_EVENT') addMonitorEvent(msg.payload as MonitorEvent);

  if (msg.type === 'MODELS_LOADED') {
    mlLoading = false;
    mlStatus  = msg.payload as MLModelStatus;
    updateMLDots();
  }

  if (msg.type === 'SCAN_STARTED') {
    activeScanId = (msg.payload as { scanId: string }).scanId;
  }

  if (msg.type === 'SCAN_PROGRESS') {
    const p = msg.payload as any;
    if (!p || p.stage === 'page_loaded') return;
    if (threatScanActive && p.phase !== undefined) {
      updateCinematicStep(p.step ?? 0, p.channelNum ?? 0, p.totalChannels ?? 12, p.path ?? '');
    } else if (p.stage !== undefined) {
      handleProgress(p.stage as string, p.pct as number, p.message as string, p);
    }
  }
});

// ── Button handlers ───────────────────────────────────────
$('btn-settings').addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('popup/settings.html') });
});

$('btn-quick').addEventListener('click',  () => startScan('quick'));
$('btn-full').addEventListener('click',   () => startScan('full'));
$('btn-threat').addEventListener('click', () => startThreatScan());

$('btn-stop').addEventListener('click', () => {
  if (!activeScanId) return;
  $('scan-status').textContent = 'Stopping...';
  chrome.runtime.sendMessage({
    type: 'SCAN_ABORT',
    payload: { scanId: activeScanId },
  } as ExtensionMessage).catch(() => {});
});

$('btn-clear-monitor').addEventListener('click', () => {
  $('monitor-list').innerHTML = '<div class="empty-state">Monitor cleared</div>';
});

$('btn-auth-toggle').addEventListener('click', () => {
  const body = $('auth-body') as HTMLElement;
  const open = body.style.display === 'none';
  body.style.display = open ? 'block' : 'none';
  ($('btn-auth-toggle') as HTMLButtonElement).style.color = open ? 'var(--acc2)' : '';
});

$('btn-clear-history').addEventListener('click', async () => {
  await chrome.storage.local.set({ scanHistory: [] });
  $('history-list').innerHTML = '<div class="empty-state">History cleared</div>';
});

document.querySelector('[data-pane="history"]')?.addEventListener('click', () => renderHistory());

$('btn-pdf').addEventListener('click',  () => { if (currentScan) generatePDFReport(currentScan); });
$('btn-json').addEventListener('click', () => { if (currentScan) exportJSON(currentScan); });

// ── Threat report action buttons ──────────────────────────
$('btn-rpt-copy').addEventListener('click', () => {
  if (!latestThreatScan) return;
  const order: Record<string, number> = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4 };
  const lines: string[] = [
    `CyberINTEL-AI — Threat Scan Report`,
    `Target:    ${latestThreatScan.domain}`,
    `Scanned:   ${new Date(latestThreatScan.scannedAt).toLocaleString()}`,
    `Score:     ${latestThreatScan.securityScore}/100  (Grade ${latestThreatScan.grade})`,
    `Findings:  ${latestThreatScan.vulnerabilities.length}`,
    '', '─'.repeat(60), '',
    ...[...latestThreatScan.vulnerabilities]
      .sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5))
      .map((v, i) => [
        `[${i + 1}] ${v.severity} — ${v.title}`,
        `    URL:  ${v.location}`,
        `    Info: ${v.description}`,
        `    Fix:  ${v.remediation}`,
        '',
      ].join('\n')),
  ];
  navigator.clipboard.writeText(lines.join('\n')).catch(() => {});
});

$('btn-rpt-export').addEventListener('click', () => {
  if (!latestThreatScan) return;
  const blob = new Blob([JSON.stringify(latestThreatScan, null, 2)], { type: 'application/json' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = `cyberintel_threat_${latestThreatScan.domain}_${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
});

$('btn-rpt-reset').addEventListener('click', () => {
  latestThreatScan = null;
  resetToNormal();
});

$('btn-cin-cancel').addEventListener('click', () => {
  if (!activeScanId) return;
  chrome.runtime.sendMessage({
    type: 'SCAN_ABORT',
    payload: { scanId: activeScanId },
  } as ExtensionMessage).catch(() => {});
  resetToNormal();
  $('scan-status').textContent = 'Threat scan aborted.';
});

// ── Scan mode controls ────────────────────────────────────
const vivaToggle = document.getElementById('viva-mode-toggle') as HTMLInputElement | null;
if (vivaToggle) {
  vivaToggle.addEventListener('change', () => {
    _vivaMode = vivaToggle.checked;
    const banner = document.getElementById('viva-mode-banner');
    if (banner) banner.style.display = _vivaMode ? 'block' : 'none';
  });
}

const speedSel = document.getElementById('reveal-speed-select') as HTMLSelectElement | null;
if (speedSel) {
  speedSel.addEventListener('change', () => {
    _revealSpeed = speedSel.value as typeof _revealSpeed;
  });
}

const analystToggle = document.getElementById('analyst-review-toggle');
if (analystToggle) {
  analystToggle.addEventListener('click', () => {
    const listEl  = document.getElementById('analyst-review-list') as HTMLElement | null;
    const arrowEl = analystToggle.querySelector('.analyst-arrow')  as HTMLElement | null;
    if (!listEl) return;
    const open = listEl.style.display !== 'none';
    listEl.style.display  = open ? 'none' : 'block';
    if (arrowEl) arrowEl.textContent = open ? '▶' : '▼';
  });
}

// ── Init ──────────────────────────────────────────────────
async function init() {
  const [tabResult, scanResult, storageResult, settingsResult] = await Promise.allSettled([
    chrome.tabs.query({ active: true, currentWindow: true }),
    chrome.runtime.sendMessage({ type: 'GET_LATEST_SCAN' } as ExtensionMessage),
    chrome.storage.local.get('monitorEvents'),
    chrome.storage.local.get('settings'),
  ]);

  if (tabResult.status === 'fulfilled') {
    const [tab] = tabResult.value;
    currentTab = tab ?? null;
    if (tab?.url) {
      try { $('target-domain').textContent = new URL(tab.url).hostname; }
      catch { $('target-domain').textContent = tab.url; }
      $('target-url').textContent = tab.url;
      const https = tab.url.startsWith('https://');
      const badge = $('proto-badge');
      badge.textContent = https ? 'HTTPS' : 'HTTP';
      badge.className   = `proto-badge ${https ? 'secure' : 'insecure'}`;
    }
  } else {
    $('target-domain').textContent = 'Unknown target';
  }

  if (scanResult.status === 'fulfilled' && scanResult.value?.payload) {
    displayScan(scanResult.value.payload as ScanResult);
  }

  if (storageResult.status === 'fulfilled') {
    const { monitorEvents = [] } = storageResult.value as { monitorEvents: MonitorEvent[] };
    monitorEvents.slice(0, 50).forEach(evt => addMonitorEvent(evt));
  }

  if (settingsResult.status === 'fulfilled') {
    const theme = (settingsResult.value.settings as any)?.theme ?? 'dark';
    document.documentElement.setAttribute('data-theme', theme);
  }

  chrome.runtime.sendMessage({ type: 'ML_STATUS_REQUEST' } as ExtensionMessage)
    .then(resp => {
      if (resp?.payload) {
        mlLoading = false;
        mlStatus  = resp.payload as MLModelStatus;
        updateMLDots();
      }
    })
    .catch(() => { mlLoading = false; updateMLDots(); });
}

init();
