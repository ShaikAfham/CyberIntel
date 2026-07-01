// ============================================================
// CyberINTEL-AI — Content Script: Real-Time Monitor
// Injected at document_start. Watches for dynamic changes
// that indicate malicious behavior — what a SOC analyst
// would flag during live incident response.
// ============================================================

import {
  MonitorEvent,
  MonitorEventType,
  Severity,
  ExtensionMessage,
} from '../types/index';

let eventCounter = 0;
const MAX_EVENTS_PER_SESSION = 500;

function generateEventId(): string {
  return `evt-${Date.now()}-${++eventCounter}`;
}

function sendEvent(event: MonitorEvent): void {
  if (eventCounter > MAX_EVENTS_PER_SESSION) return;

  const message: ExtensionMessage = {
    type:    'MONITOR_EVENT',
    payload: event,
  };

  chrome.runtime.sendMessage(message).catch(() => {
    // Service worker may be inactive — non-fatal
  });
}

// ─── 1. DOM Mutation Observer ────────────────────────────
// Watches for new scripts, iframes, and hidden elements
// being injected into the DOM dynamically.

const mutationObserver = new MutationObserver((mutations) => {
  for (const mutation of mutations) {
    for (const node of Array.from(mutation.addedNodes)) {
      if (!(node instanceof HTMLElement)) continue;

      // New <script> tag injected
      if (node.tagName === 'SCRIPT') {
        const scriptEl = node as HTMLScriptElement;
        const src = scriptEl.src;

        sendEvent({
          id:          generateEventId(),
          type:        src ? MonitorEventType.NEW_SCRIPT_LOADED : MonitorEventType.INLINE_SCRIPT_INJECTED,
          description: src
            ? `New external script loaded: ${src}`
            : `Inline script injected into DOM (${scriptEl.textContent?.slice(0, 100)}...)`,
          severity:    src ? Severity.MEDIUM : Severity.HIGH,
          timestamp:   Date.now(),
          url:         window.location.href,
          data:        { src: src || null, snippet: scriptEl.textContent?.slice(0, 200) || null },
        });
      }

      // New hidden <iframe> injected
      if (node.tagName === 'IFRAME') {
        const iframeEl = node as HTMLIFrameElement;
        const style    = window.getComputedStyle(iframeEl);
        const isHidden = style.display === 'none' ||
                         style.visibility === 'hidden' ||
                         parseInt(style.width) < 5 ||
                         parseInt(style.height) < 5;

        if (isHidden) {
          sendEvent({
            id:          generateEventId(),
            type:        MonitorEventType.NEW_IFRAME,
            description: `Hidden iframe dynamically injected: src="${iframeEl.src}"`,
            severity:    Severity.HIGH,
            timestamp:   Date.now(),
            url:         window.location.href,
            data:        { src: iframeEl.src, hidden: true },
          });
        } else {
          sendEvent({
            id:          generateEventId(),
            type:        MonitorEventType.NEW_IFRAME,
            description: `Iframe dynamically injected: src="${iframeEl.src}"`,
            severity:    Severity.LOW,
            timestamp:   Date.now(),
            url:         window.location.href,
            data:        { src: iframeEl.src, hidden: false },
          });
        }
      }
    }
  }
});

mutationObserver.observe(document.documentElement, {
  childList: true,
  subtree:   true,
});

// ─── 2. Navigation Detection ──────────────────────────────
window.addEventListener('beforeunload', () => {
  sendEvent({
    id:          generateEventId(),
    type:        MonitorEventType.REDIRECT_DETECTED,
    description: `Page navigating away from ${window.location.href}`,
    severity:    Severity.INFO,
    timestamp:   Date.now(),
    url:         window.location.href,
    data:        {},
  });
});

// ─── 3. Form Submission Monitoring ───────────────────────
document.addEventListener('submit', (event) => {
  const form = event.target as HTMLFormElement;
  const action = form?.action || window.location.href;
  const isHTTP = action.startsWith('http://');

  sendEvent({
    id:          generateEventId(),
    type:        MonitorEventType.FORM_SUBMISSION,
    description: `Form submitted to: ${action}${isHTTP ? ' ⚠️ (unencrypted HTTP)' : ''}`,
    severity:    isHTTP ? Severity.HIGH : Severity.INFO,
    timestamp:   Date.now(),
    url:         window.location.href,
    data:        { action, method: form?.method || 'GET', isHTTP },
  });
}, true);

// ─── 4. Fetch / XHR Interception ─────────────────────────
// Only log cross-origin requests to avoid flooding on SPAs.

function isCrossOrigin(requestUrl: string): boolean {
  try { return new URL(requestUrl).hostname !== window.location.hostname; }
  catch { return false; }
}

const originalFetch = window.fetch;
window.fetch = async function(...args: Parameters<typeof fetch>) {
  const url = typeof args[0] === 'string' ? args[0] : (args[0] as Request).url;

  if (isCrossOrigin(url)) {
    sendEvent({
      id:          generateEventId(),
      type:        MonitorEventType.FETCH_REQUEST,
      description: `fetch() → ${url}`,
      severity:    Severity.INFO,
      timestamp:   Date.now(),
      url:         window.location.href,
      data:        { requestUrl: url, method: (args[1] as RequestInit)?.method || 'GET' },
    });
  }

  return originalFetch.apply(window, args);
};

const originalOpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(
  method: string,
  url: string | URL,
  ...rest: [boolean?, string?, string?]
) {
  const urlStr = url.toString();
  if (isCrossOrigin(urlStr)) {
    sendEvent({
      id:          generateEventId(),
      type:        MonitorEventType.XHR_REQUEST,
      description: `XHR ${method} → ${urlStr}`,
      severity:    Severity.INFO,
      timestamp:   Date.now(),
      url:         window.location.href,
      data:        { requestUrl: urlStr, method },
    });
  }

  return originalOpen.apply(this, [method, url, ...(rest as [boolean, string?, string?])]);
};

// ─── 5. localStorage / sessionStorage Write Monitor ──────
function patchStorage(storage: Storage, name: string) {
  const originalSetItem = storage.setItem.bind(storage);
  storage.setItem = function(key: string, value: string) {
    sendEvent({
      id:          generateEventId(),
      type:        MonitorEventType.STORAGE_WRITE,
      description: `${name}.setItem("${key}", ...) — ${value.length} bytes`,
      severity:    Severity.INFO,
      timestamp:   Date.now(),
      url:         window.location.href,
      data:        { storage: name, key, valueLength: value.length },
    });
    return originalSetItem(key, value);
  };
}

patchStorage(localStorage, 'localStorage');
patchStorage(sessionStorage, 'sessionStorage');

// ─── 6. Obfuscation Detection ─────────────────────────────
// eval() and Function() constructor usage is a red flag.

const originalEval = window.eval;
(window as any).eval = function(code: string) {
  sendEvent({
    id:          generateEventId(),
    type:        MonitorEventType.INLINE_SCRIPT_INJECTED,
    description: `eval() called — possible obfuscated code execution`,
    severity:    Severity.CRITICAL,
    timestamp:   Date.now(),
    url:         window.location.href,
    data:        { snippet: code.slice(0, 200) },
  });
  return originalEval.call(window, code);
};

// ─── Cleanup on page unload ────────────────────────────
window.addEventListener('unload', () => {
  mutationObserver.disconnect();
});
