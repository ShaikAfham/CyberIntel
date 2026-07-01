// ============================================================
// CyberINTEL-AI — Content Script: Scanner
// Injected into every page. Returns comprehensive DOM security
// data when triggered by the background service worker.
// ============================================================

import {
  DOMScanResult, FormAnalysis, ScriptAnalysis,
  IframeAnalysis, InputAnalysis, LinkAnalysis, ExtensionMessage,
} from '../types/index';

const XSS_PATTERNS: RegExp[] = [
  /<script[\s\S]*?>/i, /javascript\s*:/i, /on\w+\s*=/i,
  /eval\s*\(/i, /document\.cookie/i, /document\.write/i,
  /innerHTML\s*=/i, /outerHTML\s*=/i, /insertAdjacentHTML/i,
  /execScript/i, /window\.location\s*=/i, /fromCharCode/i,
  /&#x?\d+;/i, /%3Cscript/i, /<script/i,
  /data:text\/html/i, /vbscript\s*:/i, /expression\s*\(/i,
];

const SUSPICIOUS_DOMAINS: RegExp[] = [
  /cdn\.popcash\.net/i, /propellerads\.com/i, /exoclick\.com/i,
  /trafficjunky\.net/i, /adnxs\.com/i,
];

const TRACKER_SERVICES: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /google-analytics\.com/i,   name: 'Google Analytics' },
  { pattern: /googletagmanager\.com/i,   name: 'Google Tag Manager' },
  { pattern: /connect\.facebook\.net/i,  name: 'Facebook Pixel' },
  { pattern: /hotjar\.com/i,             name: 'Hotjar' },
  { pattern: /clarity\.ms/i,            name: 'Microsoft Clarity' },
  { pattern: /doubleclick\.net/i,        name: 'DoubleClick' },
  { pattern: /adservice\.google\.com/i,  name: 'Google Ad Services' },
  { pattern: /ads\.twitter\.com/i,       name: 'Twitter Ads' },
  { pattern: /snap\.licdn\.com/i,        name: 'LinkedIn Insight' },
  { pattern: /mc\.yandex\.ru/i,          name: 'Yandex Metrica' },
  { pattern: /segment\.com/i,            name: 'Segment' },
  { pattern: /mixpanel\.com/i,           name: 'Mixpanel' },
  { pattern: /intercom\.io/i,            name: 'Intercom' },
  { pattern: /crisp\.chat/i,             name: 'Crisp Chat' },
];

const JWT_PATTERN = /^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/;

function decodeJWTHeader(token: string): string | null {
  try {
    const header = token.split('.')[0];
    const padded = header + '='.repeat((4 - header.length % 4) % 4);
    const decoded = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
    const parsed  = JSON.parse(decoded);
    return parsed.alg ?? null;
  } catch { return null; }
}

function getSelector(el: Element): string {
  if (el.id) return `#${el.id}`;
  if (el.className) return `${el.tagName.toLowerCase()}.${String(el.className).split(' ')[0]}`;
  return el.tagName.toLowerCase();
}

class PageScanner {
  private domain = window.location.hostname;
  private isHTTPS = window.location.protocol === 'https:';

  async scan(): Promise<DOMScanResult> {
    return {
      forms:          this.scanForms(),
      scripts:        this.scanScripts(),
      iframes:        this.scanIframes(),
      links:          this.scanLinks(),
      inputs:         this.scanInputs(),
      localStorage:   this.scanLocalStorage(),
      sessionStorage: this.scanSessionStorage(),
      trackers:       this.scanTrackers(),
      mixedContent:   this.scanMixedContent(),
      jwtTokens:      this.scanJWTTokens(),
      pageTitle:      document.title,
      faviconUrl:     this.getFaviconUrl(),
      isHTTPS:        this.isHTTPS,
    };
  }

  private scanForms(): FormAnalysis[] {
    return Array.from(document.querySelectorAll<HTMLFormElement>('form')).map(form => {
      const inputs       = Array.from(form.querySelectorAll<HTMLInputElement>('input'));
      const hiddenInputs = inputs.filter(i => i.type === 'hidden');
      const hasCsrf      = hiddenInputs.some(i =>
        /csrf|token|_token|authenticity|nonce/i.test(i.name || i.id || '')
      );
      return {
        action:          form.action || '',
        method:          (form.method || 'GET').toUpperCase(),
        hasPasswordField: inputs.some(i => i.type === 'password'),
        submitsOverHTTP:  (form.action || '').startsWith('http://'),
        hasAutocomplete:  form.autocomplete !== 'off',
        hasCsrfToken:     hasCsrf,
        selector:         getSelector(form),
      };
    });
  }

  private scanScripts(): ScriptAnalysis[] {
    return Array.from(document.querySelectorAll<HTMLScriptElement>('script')).map(script => {
      const src        = script.src || null;
      const isInline   = !src && !!script.textContent?.trim();
      const isExternal = !!src;
      let domain: string | null = null;
      if (src) { try { domain = new URL(src).hostname; } catch { /* */ } }
      const isThirdParty = domain ? domain !== this.domain : false;
      const isSuspDomain = domain ? SUSPICIOUS_DOMAINS.some(p => p.test(domain!)) : false;
      const snippet      = isInline ? (script.textContent?.slice(0, 200) ?? null) : null;
      const hasXSS       = snippet ? XSS_PATTERNS.some(p => p.test(snippet)) : false;
      return {
        src, isInline, isExternal, domain,
        isSuspicious:   isSuspDomain || (isInline && hasXSS),
        suspicionReason: isSuspDomain
          ? `Suspicious ad/tracker domain: ${domain}`
          : hasXSS ? 'Inline script contains potential XSS pattern' : null,
        snippet,
      };
    });
  }

  private scanIframes(): IframeAnalysis[] {
    return Array.from(document.querySelectorAll<HTMLIFrameElement>('iframe')).map(iframe => {
      const src    = iframe.src || null;
      const style  = window.getComputedStyle(iframe);
      const isHidden = style.display === 'none' || style.visibility === 'hidden' ||
        parseInt(style.width || '100') < 5 || parseInt(style.height || '100') < 5;
      let isThirdParty = false;
      if (src) { try { isThirdParty = new URL(src).hostname !== this.domain; } catch { /* */ } }
      return { src, isSandboxed: iframe.hasAttribute('sandbox'), isHidden, isThirdParty };
    });
  }

  private scanLinks(): LinkAnalysis[] {
    const results: LinkAnalysis[] = [];
    for (const a of Array.from(document.querySelectorAll<HTMLAnchorElement>('a[href]')).slice(0, 200)) {
      const href = a.href;
      let isExternal = false;
      try { isExternal = new URL(href).hostname !== this.domain; } catch { /* */ }
      const isSuspicious = /javascript\s*:/i.test(href) || /data:/i.test(href) || /vbscript\s*:/i.test(href);
      if (isSuspicious || isExternal) results.push({ href, isExternal, isSuspicious });
    }
    return results;
  }

  private scanInputs(): InputAnalysis[] {
    return Array.from(document.querySelectorAll<HTMLInputElement>('input, textarea')).map(input => {
      const value  = input.value || '';
      const hasXSS = XSS_PATTERNS.some(p => p.test(value));
      return {
        type:          input.type || 'text',
        name:          input.name || input.id || '(unnamed)',
        hasXSSPayload: hasXSS,
        payload:       hasXSS ? value.slice(0, 200) : null,
      };
    });
  }

  private scanLocalStorage(): Record<string, string> {
    const data: Record<string, string> = {};
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key) data[key] = (localStorage.getItem(key) || '').slice(0, 500);
      }
    } catch { /* sandboxed */ }
    return data;
  }

  private scanSessionStorage(): Record<string, string> {
    const data: Record<string, string> = {};
    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (key) data[key] = (sessionStorage.getItem(key) || '').slice(0, 500);
      }
    } catch { /* sandboxed */ }
    return data;
  }

  private scanTrackers(): Array<{ src: string; service: string }> {
    const found: Array<{ src: string; service: string }> = [];
    document.querySelectorAll<HTMLScriptElement>('script[src]').forEach(s => {
      const src = s.src;
      for (const tracker of TRACKER_SERVICES) {
        if (tracker.pattern.test(src)) {
          found.push({ src, service: tracker.name });
          break;
        }
      }
    });
    return found;
  }

  private scanMixedContent(): Array<{ tag: string; url: string }> {
    if (!this.isHTTPS) return [];
    const mixed: Array<{ tag: string; url: string }> = [];
    const checks: Array<{ sel: string; attr: string }> = [
      { sel: 'img[src]',    attr: 'src'  },
      { sel: 'script[src]', attr: 'src'  },
      { sel: 'link[href]',  attr: 'href' },
      { sel: 'iframe[src]', attr: 'src'  },
      { sel: 'audio[src]',  attr: 'src'  },
      { sel: 'video[src]',  attr: 'src'  },
    ];
    for (const { sel, attr } of checks) {
      document.querySelectorAll<HTMLElement>(sel).forEach(el => {
        const url = el.getAttribute(attr) || '';
        if (url.startsWith('http://')) {
          mixed.push({ tag: sel.split('[')[0], url });
        }
      });
    }
    return mixed;
  }

  private scanJWTTokens(): Array<{ location: string; token: string; alg: string | null }> {
    const tokens: Array<{ location: string; token: string; alg: string | null }> = [];

    const checkValue = (value: string, location: string) => {
      // JWT can be bare or in "Bearer <token>" format
      const candidates = [value, ...(value.match(/Bearer\s+(\S+)/i) || []).slice(1)];
      for (const candidate of candidates) {
        if (JWT_PATTERN.test(candidate.trim())) {
          const alg = decodeJWTHeader(candidate.trim());
          tokens.push({ location, token: candidate.trim().slice(0, 100) + '...', alg });
          break;
        }
      }
    };

    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i)!;
        checkValue(localStorage.getItem(key) || '', `localStorage["${key}"]`);
      }
    } catch { /* */ }

    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i)!;
        checkValue(sessionStorage.getItem(key) || '', `sessionStorage["${key}"]`);
      }
    } catch { /* */ }

    document.cookie.split(';').forEach(c => {
      const [name, ...rest] = c.trim().split('=');
      checkValue(rest.join('='), `cookie["${name.trim()}"]`);
    });

    return tokens;
  }

  private getFaviconUrl(): string | null {
    const link = document.querySelector<HTMLLinkElement>('link[rel~="icon"]');
    if (!link) return null;
    try {
      const href = link.href;
      const domain = new URL(href).hostname;
      return domain !== this.domain ? href : null;
    } catch { return null; }
  }
}

// ─── Entry Point ─────────────────────────────────────────
(async () => {
  const scanner = new PageScanner();

  chrome.runtime.onMessage.addListener((message: ExtensionMessage, _sender, sendResponse) => {
    if (message.type === 'SCAN_REQUEST') {
      (async () => {
        try {
          const domResult = await scanner.scan();
          sendResponse({ type: 'SCAN_RESULT', payload: { domResult } });
        } catch (err) {
          sendResponse({ type: 'SCAN_RESULT', error: String(err) });
        }
      })();
      return true;
    }
    return false;
  });

  // Notify background of page metadata
  chrome.runtime.sendMessage({
    type: 'SCAN_PROGRESS',
    payload: {
      stage: 'page_loaded',
      metadata: {
        url:     window.location.href,
        title:   document.title,
        domain:  window.location.hostname,
        isHTTPS: window.location.protocol === 'https:',
      },
    },
  }).catch(() => {});
})();
