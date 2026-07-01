// CyberINTEL-AI — Settings Page
// Extracted from inline script to satisfy MV3 script-src 'self' CSP.

interface UserSettings {
  enableMLScans: boolean;
  autoScanOnVisit: boolean;
  openPageDuringScan: boolean;
  enableRealTimeMonitoring: boolean;
  enableNotifications: boolean;
  scanSensitivity: 'low' | 'medium' | 'high';
  backendUrl: string | null;
  theme: 'dark' | 'light';
}

function el<T extends HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

async function loadSettings(): Promise<void> {
  const data     = await chrome.storage.local.get('settings');
  const s: Partial<UserSettings> = data.settings ?? {};

  el<HTMLInputElement>('enableMLScans').checked            = s.enableMLScans ?? true;
  el<HTMLInputElement>('autoScanOnVisit').checked          = s.autoScanOnVisit ?? false;
  el<HTMLInputElement>('openPageDuringScan').checked       = s.openPageDuringScan ?? false;
  el<HTMLInputElement>('enableRealTimeMonitoring').checked = s.enableRealTimeMonitoring ?? true;
  el<HTMLInputElement>('enableNotifications').checked      = s.enableNotifications ?? true;
  el<HTMLSelectElement>('scanSensitivity').value           = s.scanSensitivity ?? 'medium';
  el<HTMLInputElement>('backendUrl').value                 = s.backendUrl ?? 'http://localhost:8000';
  el<HTMLSelectElement>('theme').value                     = s.theme ?? 'dark';
}

el('btn-save').addEventListener('click', async () => {
  const settings: UserSettings = {
    enableMLScans:            el<HTMLInputElement>('enableMLScans').checked,
    autoScanOnVisit:          el<HTMLInputElement>('autoScanOnVisit').checked,
    openPageDuringScan:       el<HTMLInputElement>('openPageDuringScan').checked,
    enableRealTimeMonitoring: el<HTMLInputElement>('enableRealTimeMonitoring').checked,
    enableNotifications:      el<HTMLInputElement>('enableNotifications').checked,
    scanSensitivity:          el<HTMLSelectElement>('scanSensitivity').value as 'low' | 'medium' | 'high',
    backendUrl:               el<HTMLInputElement>('backendUrl').value || 'http://localhost:8000',
    theme:                    el<HTMLSelectElement>('theme').value as 'dark' | 'light',
  };
  await chrome.storage.local.set({ settings });
  const banner = el('saved-banner');
  banner.style.display = 'block';
  setTimeout(() => { banner.style.display = 'none'; }, 2000);
});

el('btn-clear').addEventListener('click', async () => {
  if (confirm('Clear all scan history and monitor events?')) {
    await chrome.storage.local.set({ scanHistory: [], monitorEvents: [] });
    alert('History cleared.');
  }
});

function applyModelStatus(status: Record<string, boolean> | null): void {
  ['xss', 'phishing', 'anomaly'].forEach(name => {
    const dot = el(`dot-${name}`);
    const txt = el(`status-${name}`);
    if (status?.[name]) {
      dot.className    = 'model-dot loaded';
      txt.textContent  = 'Loaded ✓';
      txt.style.color  = '#30d158';
    } else {
      dot.className    = 'model-dot missing';
      txt.textContent  = 'Not loaded';
      txt.style.color  = '#ff9500';
    }
  });
}

async function checkModelStatus(): Promise<void> {
  try {
    const data = await chrome.storage.local.get('modelStatus');
    if (data.modelStatus) {
      applyModelStatus(data.modelStatus as Record<string, boolean>);
      return;
    }
    const response = await chrome.runtime.sendMessage({ type: 'ML_STATUS_REQUEST' });
    applyModelStatus((response?.payload as Record<string, boolean>) ?? null);
  } catch {
    document.querySelectorAll<HTMLElement>('.model-dot')
      .forEach(d => { d.className = 'model-dot error'; });
    ['xss', 'phishing', 'anomaly'].forEach(name => {
      const txt = document.getElementById(`status-${name}`);
      if (txt) { txt.textContent = 'Error checking'; txt.style.color = '#ff3b30'; }
    });
  }
}

loadSettings();
checkModelStatus();
