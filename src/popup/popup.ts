import './popup.css';
import { ScanResult, ExtensionMessage } from '../types/index';

const $ = (id: string): HTMLElement => document.getElementById(id)!;

let currentTab: chrome.tabs.Tab | null = null;

// ── Score ring (compact r=32, circumference=201) ───────────
function setScore(score: number, grade: string) {
  const CIRC   = 201;
  const offset = CIRC - (score / 100) * CIRC;
  const ring   = $('score-ring-fill') as unknown as SVGCircleElement;
  ring.style.strokeDashoffset = String(offset);
  const c = grade === 'A' || grade === 'B' ? '#30d158'
           : grade === 'C' ? '#ffcc00'
           : grade === 'D' ? '#ff8c00' : '#ff3b46';
  ring.style.stroke           = c;
  $('score-value').textContent = String(score);
  $('score-grade').textContent = grade;
  ($('score-grade') as HTMLElement).style.color = c;
}

function displayScan(scan: ScanResult) {
  setScore(scan.securityScore, scan.grade);
  $('cnt-crit').textContent = String(scan.counts.critical);
  $('cnt-high').textContent = String(scan.counts.high);
  $('cnt-med').textContent  = String(scan.counts.medium);
  $('cnt-low').textContent  = String(scan.counts.low);
  $('scan-status').textContent =
    `${scan.vulnerabilities.length} finding${scan.vulnerabilities.length !== 1 ? 's' : ''} — ${scan.domain}`;
}

// ── Settings ───────────────────────────────────────────────
$('btn-settings').addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('popup/settings.html') });
});

// ── Quick Scan (rule-based only, no ML) ────────────────────
($('btn-scan') as HTMLButtonElement).addEventListener('click', async () => {
  if (!currentTab?.id) return;
  const btn = $('btn-scan') as HTMLButtonElement;
  const msg = $('scan-msg');
  btn.disabled     = true;
  btn.textContent  = 'Scanning...';
  msg.textContent  = '';
  $('scan-status').textContent = 'Running scan...';

  try {
    const resp = await chrome.runtime.sendMessage({
      type: 'SCAN_REQUEST', tabId: currentTab.id,
    } as ExtensionMessage);

    if (resp?.payload) {
      displayScan(resp.payload as ScanResult);
      msg.textContent = 'Done. Open Dashboard for full AI/ML analysis.';
    } else {
      $('scan-status').textContent = resp?.error ?? 'Scan failed';
    }
  } catch (err) {
    $('scan-status').textContent = `Error: ${String(err)}`;
  } finally {
    btn.disabled    = false;
    btn.textContent = '▶ Quick Scan';
  }
});

// ── Open side panel dashboard ──────────────────────────────
($('btn-dashboard') as HTMLButtonElement).addEventListener('click', async () => {
  try {
    if (currentTab?.id) {
      await (chrome.sidePanel as any).open({ tabId: currentTab.id });
    } else {
      await (chrome.sidePanel as any).open({});
    }
    window.close();
  } catch {
    chrome.tabs.create({ url: chrome.runtime.getURL('sidepanel/sidepanel.html') });
    window.close();
  }
});

// ── Init ───────────────────────────────────────────────────
async function init() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTab = tab;
    if (tab?.url) {
      try { $('current-url').textContent = new URL(tab.url).hostname; }
      catch { $('current-url').textContent = tab.url; }
      const https = tab.url.startsWith('https://');
      const badge = $('proto-badge');
      badge.textContent = https ? 'HTTPS' : 'HTTP';
      badge.className   = `proto-badge ${https ? 'secure' : 'insecure'}`;
    }
    const resp = await chrome.runtime.sendMessage({ type: 'GET_LATEST_SCAN' } as ExtensionMessage);
    if (resp?.payload) displayScan(resp.payload as ScanResult);
  } catch {
    $('scan-status').textContent = 'Cannot access tab';
  }
}

init();
