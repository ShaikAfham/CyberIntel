// CyberINTEL-AI — Target Tab Security Overlay
// Injected into scanned tabs via chrome.scripting.executeScript
// Uses Shadow DOM to prevent CSS conflicts with the target page

(function cyberIntelOverlay() {
  if ((window as any).__ci_overlay) return;
  (window as any).__ci_overlay = true;

  const STATUS_CYCLE = [
    'INITIALIZING SCAN PROTOCOLS...',
    'PROBING TARGET SURFACE...',
    'ANALYZING HTTP HEADERS...',
    'EVALUATING SSL/TLS CONFIGURATION...',
    'AUDITING COOKIE ATTRIBUTES...',
    'SCANNING DOM FOR INJECTION VECTORS...',
    'RUNNING XSS DETECTION ENGINE...',
    'PHISHING PATTERN ANALYSIS...',
    'BEHAVIORAL ANOMALY DETECTION...',
    'ENUMERATING SENSITIVE ENDPOINTS...',
    'INSPECTING JAVASCRIPT INTEGRITY...',
    'CORRELATING FINDINGS...',
    'COMPUTING SECURITY SCORE...',
    'FINALIZING THREAT REPORT...',
  ];

  // ── Build host element ─────────────────────────────────────
  const host = document.createElement('div');
  host.style.cssText =
    'position:fixed;top:0;left:0;width:100%;height:100%;z-index:2147483647;' +
    'pointer-events:none;font-family:"JetBrains Mono","Courier New",monospace;';
  document.documentElement.appendChild(host);

  const shadow = host.attachShadow({ mode: 'open' });

  // ── Styles ────────────────────────────────────────────────
  const style = document.createElement('style');
  style.textContent = `
    * { box-sizing: border-box; margin: 0; padding: 0; }

    .ci-root {
      position: fixed;
      inset: 0;
      background: rgba(0,6,30,0.94);
      font-family: "JetBrains Mono","Courier New",monospace;
      color: #00ccff;
      overflow: hidden;
      pointer-events: none;
    }

    /* Scanline overlay */
    .ci-root::before {
      content: '';
      position: absolute;
      inset: 0;
      background: repeating-linear-gradient(
        0deg,
        transparent 0px, transparent 3px,
        rgba(0,0,0,0.15) 3px, rgba(0,0,0,0.15) 4px
      );
      pointer-events: none;
      z-index: 1;
    }

    /* Corner brackets */
    .corner { position: absolute; width: 22px; height: 22px; z-index: 20; }
    .c-tl { top:0;    left:0;   border-top:2px solid #06b6d4; border-left:2px solid #06b6d4; }
    .c-tr { top:0;    right:0;  border-top:2px solid #06b6d4; border-right:2px solid #06b6d4; }
    .c-bl { bottom:0; left:0;   border-bottom:2px solid #06b6d4; border-left:2px solid #06b6d4; }
    .c-br { bottom:0; right:0;  border-bottom:2px solid #06b6d4; border-right:2px solid #06b6d4; }

    /* Horizontal scanning beam */
    .beam {
      position: absolute; left: 0; top: 0; width: 100%; height: 2px;
      background: linear-gradient(90deg,
        transparent 0%, rgba(6,182,212,0.12) 20%,
        rgba(0,255,255,0.65) 50%, rgba(6,182,212,0.12) 80%, transparent 100%
      );
      animation: beam 2.8s linear infinite;
      z-index: 2;
    }
    @keyframes beam { 0% { top: 0%; } 100% { top: 100%; } }

    /* Header */
    .ci-header { position: absolute; top: 18px; left: 24px; z-index: 10; }

    .ci-title {
      font-size: 13px; font-weight: 700; color: #00ffff;
      letter-spacing: 0.14em; text-transform: uppercase;
      overflow: hidden; white-space: nowrap;
      border-right: 2px solid #00ffff;
      width: 0;
      animation: typing 1.4s steps(38, end) 0.2s forwards, blink-cursor 0.75s step-end infinite 1.6s;
    }
    @keyframes typing    { to { width: 100%; } }
    @keyframes blink-cursor { 0%,100% { border-color: #00ffff; } 50% { border-color: transparent; } }

    .ci-url {
      font-size: 11px; color: rgba(6,182,212,0.55); margin-top: 5px;
      letter-spacing: 0.04em; max-width: 55vw;
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }

    /* Close button — pointer-events enabled */
    .ci-close {
      position: absolute; top: 16px; right: 24px;
      background: rgba(255,0,60,0.08); border: 1px solid rgba(255,0,60,0.45);
      color: #ff3c5a; padding: 5px 14px;
      font-family: "JetBrains Mono", monospace; font-size: 11px;
      letter-spacing: 0.08em; cursor: pointer; pointer-events: auto;
      z-index: 30; transition: background 0.15s;
    }
    .ci-close:hover { background: rgba(255,0,60,0.2); }

    /* Radar — left panel */
    .ci-radar {
      position: absolute; top: 50%; left: 30%;
      transform: translate(-50%, -58%);
      width: 180px; height: 180px; z-index: 5;
    }
    .ci-ring {
      position: absolute; top: 50%; left: 50%; border-radius: 50%;
      border: 1.5px solid rgba(0,255,136,0.55);
      animation: ring-expand 2.2s ease-out infinite;
      transform: translate(-50%,-50%) scale(0.1);
    }
    .ci-ring:nth-child(1) { width:40px;  height:40px;  animation-delay:0s;    }
    .ci-ring:nth-child(2) { width:80px;  height:80px;  animation-delay:0.44s; }
    .ci-ring:nth-child(3) { width:120px; height:120px; animation-delay:0.88s; }
    .ci-ring:nth-child(4) { width:160px; height:160px; animation-delay:1.32s; }
    .ci-ring:nth-child(5) { width:200px; height:200px; animation-delay:1.76s; }
    @keyframes ring-expand {
      0%   { opacity:0.85; transform:translate(-50%,-50%) scale(0.2); }
      100% { opacity:0;    transform:translate(-50%,-50%) scale(1.5); }
    }
    .ci-sweep {
      position:absolute; top:50%; left:50%; width:50%; height:1px;
      transform-origin:0% 50%;
      background:linear-gradient(90deg, rgba(0,255,136,0.9), transparent);
      animation:sweep 2s linear infinite;
    }
    @keyframes sweep { 0% { transform:rotate(0deg); } 100% { transform:rotate(360deg); } }
    .ci-dot {
      position:absolute; top:50%; left:50%;
      transform:translate(-50%,-50%);
      width:7px; height:7px; background:#00ff88; border-radius:50%;
      box-shadow:0 0 10px #00ff88, 0 0 22px rgba(0,255,136,0.5);
    }

    /* Progress bar */
    .ci-progress-wrap {
      position:absolute; bottom:72px; left:24px; right:calc(38% + 24px);
      z-index: 10;
    }
    .ci-progress-label {
      font-size:10px; color:rgba(6,182,212,0.6); letter-spacing:0.1em;
      margin-bottom:5px; display:flex; justify-content:space-between;
    }
    .ci-progress-track {
      height:3px; background:rgba(6,182,212,0.15); border-radius:2px;
    }
    .ci-progress-fill {
      height:100%; width:0%;
      background:linear-gradient(90deg, #06b6d4, #00ffff);
      box-shadow:0 0 8px #00ffff;
      border-radius:2px;
      transition:width 0.4s ease;
    }

    /* Bottom status bar */
    .ci-bar {
      position:absolute; bottom:0; left:0; right:0;
      background:rgba(0,0,10,0.88); border-top:1px solid rgba(6,182,212,0.18);
      padding:11px 24px; z-index:10; display:flex; align-items:center; gap:10px;
    }
    .ci-blink {
      width:6px; height:6px; background:#00ff88; border-radius:50%;
      animation:blink 0.75s step-end infinite; flex-shrink:0;
    }
    @keyframes blink { 0%,100%{opacity:1;} 50%{opacity:0;} }
    .ci-status { font-size:12px; color:#00ff88; letter-spacing:0.1em; transition:opacity 0.2s; }

    /* Terminal log — right panel */
    .ci-terminal {
      position:absolute; top:54px; right:0; width:38%; bottom:48px;
      border-left:1px solid rgba(6,182,212,0.14);
      background:rgba(0,4,18,0.7); z-index:10;
      display:flex; flex-direction:column; overflow:hidden;
    }
    .ci-terminal-title {
      font-size:10px; font-weight:700; letter-spacing:0.15em;
      color:rgba(6,182,212,0.5); padding:10px 14px 8px;
      border-bottom:1px solid rgba(6,182,212,0.1);
      flex-shrink:0;
    }
    .ci-terminal-list {
      flex:1; overflow-y:auto; padding:8px 14px;
      display:flex; flex-direction:column; gap:5px;
    }
    .ci-terminal-list::-webkit-scrollbar { width:3px; }
    .ci-terminal-list::-webkit-scrollbar-thumb { background:rgba(6,182,212,0.3); }
    .ci-finding {
      font-size:10px; letter-spacing:0.04em; padding:4px 8px;
      border-left:2px solid #06b6d4; background:rgba(6,182,212,0.05);
      animation:fade-in 0.3s ease;
    }
    @keyframes fade-in { from{opacity:0;transform:translateX(6px);} to{opacity:1;transform:none;} }
    .ci-finding.sev-critical { border-color:#ff003c; color:#ff6080; background:rgba(255,0,60,0.08); }
    .ci-finding.sev-high     { border-color:#ff6600; color:#ff9955; background:rgba(255,102,0,0.07); }
    .ci-finding.sev-medium   { border-color:#ffcc00; color:#ffdd55; background:rgba(255,204,0,0.06); }
    .ci-finding.sev-low      { border-color:#06b6d4; color:#67e8f9; }
    .ci-finding.sev-info     { border-color:#555; color:#888; }
  `;

  // ── DOM ───────────────────────────────────────────────────
  const root = document.createElement('div');
  root.className = 'ci-root';
  root.innerHTML = `
    <div class="beam"></div>
    <div class="corner c-tl"></div>
    <div class="corner c-tr"></div>
    <div class="corner c-bl"></div>
    <div class="corner c-br"></div>

    <div class="ci-header">
      <div class="ci-title">CyberINTEL-AI &nbsp;|&nbsp; SECURITY ANALYSIS IN PROGRESS</div>
      <div class="ci-url" id="ci-url">${location.href}</div>
    </div>

    <button class="ci-close" id="ci-close">&#10005; CLOSE</button>

    <div class="ci-radar">
      <div class="ci-ring"></div>
      <div class="ci-ring"></div>
      <div class="ci-ring"></div>
      <div class="ci-ring"></div>
      <div class="ci-ring"></div>
      <div class="ci-sweep"></div>
      <div class="ci-dot"></div>
    </div>

    <div class="ci-progress-wrap">
      <div class="ci-progress-label">
        <span id="ci-pct-label">SCAN PROGRESS</span>
        <span id="ci-pct-value">0%</span>
      </div>
      <div class="ci-progress-track">
        <div class="ci-progress-fill" id="ci-progress"></div>
      </div>
    </div>

    <div class="ci-terminal">
      <div class="ci-terminal-title">LIVE FINDINGS</div>
      <div class="ci-terminal-list" id="ci-terminal-list"></div>
    </div>

    <div class="ci-bar">
      <div class="ci-blink"></div>
      <div class="ci-status" id="ci-status">INITIALIZING SCAN PROTOCOLS...</div>
    </div>
  `;

  shadow.appendChild(style);
  shadow.appendChild(root);

  // ── Status cycling ───────────────────────────────────────
  let cycleIdx = 0;
  const statusEl = shadow.querySelector('#ci-status') as HTMLElement | null;

  const cycleInterval = setInterval(() => {
    if (!statusEl) return;
    statusEl.style.opacity = '0';
    setTimeout(() => {
      cycleIdx = (cycleIdx + 1) % STATUS_CYCLE.length;
      if (statusEl) {
        statusEl.textContent = STATUS_CYCLE[cycleIdx];
        statusEl.style.opacity = '1';
      }
    }, 200);
  }, 800);

  // ── Close button ─────────────────────────────────────────
  const closeBtn = shadow.querySelector('#ci-close') as HTMLButtonElement | null;
  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      clearInterval(cycleInterval);
      host.remove();
    });
  }

  // ── Message listener ─────────────────────────────────────
  chrome.runtime.onMessage.addListener((msg: { type: string; payload?: any; step?: string }) => {
    if (msg.type === 'OVERLAY_INIT') {
      const urlEl = shadow.querySelector('#ci-url') as HTMLElement | null;
      if (urlEl) urlEl.textContent = location.href;
    }

    if (msg.type === 'OVERLAY_STEP') {
      if (statusEl && msg.step) {
        statusEl.textContent = msg.step;
      }
    }

    if (msg.type === 'OVERLAY_PROGRESS') {
      const { pct, message } = msg.payload ?? {};
      const bar = shadow.querySelector('#ci-progress') as HTMLElement | null;
      const pctVal = shadow.querySelector('#ci-pct-value') as HTMLElement | null;
      if (bar && pct != null) bar.style.width = `${pct}%`;
      if (pctVal && pct != null) pctVal.textContent = `${Math.round(pct)}%`;
      if (statusEl && message) {
        statusEl.textContent = message;
      }
    }

    if (msg.type === 'OVERLAY_FINDING') {
      const f = msg.payload;
      if (!f) return;
      const list = shadow.querySelector('#ci-terminal-list') as HTMLElement | null;
      if (list) {
        const item = document.createElement('div');
        const sev = (f.severity as string || 'info').toLowerCase();
        item.className = `ci-finding sev-${sev}`;
        item.textContent = `[${(f.severity as string || 'INFO').toUpperCase()}] ${f.title ?? ''}`;
        list.prepend(item);
      }
    }

    if (msg.type === 'OVERLAY_REMOVE') {
      clearInterval(cycleInterval);
      host.style.transition = 'opacity 0.5s';
      host.style.opacity = '0';
      setTimeout(() => host.remove(), 520);
    }
  });
})();
