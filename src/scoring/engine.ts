// ============================================================
// CyberINTEL-AI — Canonical Scoring Engine
// Single source of truth for score, grade, and per-finding
// deduction. All other files delegate here.
// ============================================================

export type SeverityLC = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ConfidenceTier = 'high' | 'medium' | 'low';

export interface SubCheckFinding {
  subCheckId: string;
  checkId: string;
  title: string;
  severity: SeverityLC;
  confidence: ConfidenceTier;
  observed_or_inferred: 'observed' | 'inferred';
  evidence: string[];
  remediation: string;
}

export interface ScoreBreakdown {
  finalScore: number;
  grade: string;
  gradeLabel: string;
  totalDeduction: number;
  byCheck: Record<string, number>;
  bySubCheck: Record<string, number>;
  includedFindings: SubCheckFinding[];
  excludedFindings: SubCheckFinding[];
}

// ── Maximum points each sub-check can deduct ─────────────
export const SUB_CHECK_MAX: Record<string, number> = {
  // Headers
  'headers.csp_missing':               8,
  'headers.csp_unsafe_inline':         5,
  'headers.csp_unsafe_eval':           4,
  'headers.csp_no_default_src':        3,
  'headers.hsts_missing':              6,
  'headers.x_frame_options_missing':   3,
  'headers.x_content_type_missing':    2,
  'headers.referrer_policy_missing':   2,
  'headers.permissions_policy_missing':2,
  'headers.x_xss_protection_missing':  1,
  'headers.server_version_exposed':    3,
  'headers.x_powered_by_exposed':      2,
  'headers.cors_blocked':              0,
  // Cookies
  'cookies.session_no_secure':         6,
  'cookies.session_no_httponly':       6,
  'cookies.no_samesite':              4,
  'cookies.samesite_none_no_secure':  4,
  'cookies.auth_no_httponly':          5,
  'cookies.non_session_no_secure':     2,
  'cookies.expiry_too_long':           1,
  'cookies.no_prefix':                 2,
  // SSL / transport
  'ssl.no_https':                     10,
  // Redirects
  'redirects.no_https_redirect':       6,
  'redirects.external_domain':         5,
  'redirects.chain_too_long':          3,
  'redirects.meta_refresh':            3,
  'redirects.js_external':             4,
  // Auth
  'auth.login_over_http':             10,
  'auth.autocomplete_on':              4,
  'auth.no_token_on_protected':        6,
  'auth.token_in_url':                 7,
  'auth.no_https_on_auth_page':        9,
  'auth.basic_auth_no_https':          6,
  // CORS
  'cors.wildcard_origin':              7,
  'cors.wildcard_with_credentials':   10,
  'cors.reflects_origin':              7,
  'cors.api_misconfiguration':         6,
  'cors.preflight_not_enforced':       4,
  // CSRF
  'csrf.no_token_in_form':             7,
  'csrf.state_change_via_get':         6,
  'csrf.no_samesite_session':          4,
  'csrf.posts_to_external':            5,
  'csrf.no_custom_header':             3,
  // Session
  'session.no_expiry':                 5,
  'session.persists_after_logout':     6,
  'session.token_in_localstorage':     5,
  'session.no_timeout_signal':         4,
  // Rate limiting
  'ratelimit.no_headers_on_login':     5,
  'ratelimit.no_captcha':              4,
  'ratelimit.no_retry_after':          3,
  // DOM / Input
  'input.url_param_in_dom':            7,
  'input.reflected_in_meta':           5,
  'input.unencoded_querystring':       7,
  'input.hash_in_dom':                 5,
  'input.in_script_block':             9,
  // DOM misc
  'dom.hidden_iframe':                 6,
  // Scripts
  'scripts.suspicious_external':       4,
  // Files
  'files.env_accessible':             10,
  'files.git_config_accessible':       9,
  'files.robots_reveals_paths':        3,
  'files.sitemap_exposes_routes':      2,
  'files.backup_accessible':           6,
  'files.error_stack_trace':           5,
  'files.phpinfo_accessible':          7,
  'files.source_map_accessible':       4,
  'files.htaccess_accessible':         5,
  // Tokens
  'tokens.api_key_in_source':         10,
  'tokens.bearer_in_url':              9,
  'tokens.jwt_in_localstorage':        6,
  'tokens.jwt_alg_none':              10,
  'tokens.firebase_config_exposed':    7,
  'tokens.webhook_url_exposed':        6,
  'tokens.auth_token_inline_js':       7,
  'tokens.service_account_exposed':   10,
  // Redirect
  'redirect.param_present':            5,
  'redirect.external_target':          7,
  'redirect.js_location_from_param':   6,
  'redirect.meta_refresh_external':    5,
  // Payment
  'payment.public_key_in_html':        2,
  'payment.secret_key_in_frontend':   12,
  'payment.webhook_url_in_js':         7,
  'payment.form_over_http':           10,
  'payment.webhook_secret_exposed':   10,
  // Routes
  'routes.admin_no_auth':             10,
  'routes.api_no_auth':                7,
  'routes.internal_guessable':         5,
  'routes.api_admin_exposed':          4,
  'routes.debug_endpoint':             6,
  'routes.login_page_exposed':         2,
  // Mixed content
  'mixed_content.http_resource':       4,
  // Trackers
  'trackers.third_party':              1,
  // Phishing
  'phishing.cross_domain_form':        7,
  'phishing.cross_domain_favicon':     2,
  // ML
  'ml.xss_detected':                   8,
  'ml.phishing_detected':              8,
  'ml.anomaly_detected':               4,
  // Fallback (no deduction)
  'uncategorized':                     0,
};

const SEVERITY_MULTIPLIER: Record<SeverityLC, number> = {
  critical: 1.0, high: 0.8, medium: 0.5, low: 0.2, info: 0.0,
};

const SEVERITY_ORDER: Record<SeverityLC, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1,
};

export function deriveGrade(s: number): { grade: string; label: string } {
  if (s >= 90) return { grade: 'A', label: 'Strong' };
  if (s >= 75) return { grade: 'B', label: 'Good' };
  if (s >= 60) return { grade: 'C', label: 'Moderate' };
  if (s >= 45) return { grade: 'D', label: 'Weak' };
  if (s >= 25) return { grade: 'E', label: 'Poor' };
  return { grade: 'F', label: 'Critical Risk' };
}

export function calculateScore(
  all: SubCheckFinding[],
  strict = false,
): ScoreBreakdown {
  const inc = strict
    ? all.filter(f => f.severity === 'critical' || f.severity === 'high')
    : all;
  const exc = strict
    ? all.filter(f => f.severity !== 'critical' && f.severity !== 'high')
    : [];

  // Keep only the worst finding per sub-check (prevents double-counting)
  const worst: Record<string, SubCheckFinding> = {};
  for (const f of inc) {
    const prev = worst[f.subCheckId];
    if (!prev || SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[prev.severity]) {
      worst[f.subCheckId] = f;
    }
  }

  const bySub: Record<string, number> = {};
  const byChk: Record<string, number> = {};
  let tot = 0;

  for (const [id, f] of Object.entries(worst)) {
    const d = Math.round((SUB_CHECK_MAX[id] ?? 0) * SEVERITY_MULTIPLIER[f.severity] * 10) / 10;
    bySub[id] = d;
    byChk[f.checkId] = (byChk[f.checkId] ?? 0) + d;
    tot += d;
  }

  const final = Math.max(0, Math.min(100, Math.round(100 - tot)));
  const { grade, label } = deriveGrade(final);

  return {
    finalScore: final,
    grade,
    gradeLabel: label,
    totalDeduction: Math.round(tot * 10) / 10,
    byCheck: byChk,
    bySubCheck: bySub,
    includedFindings: inc,
    excludedFindings: exc,
  };
}

// Returns the deduction this specific finding contributes.
// Returns 0 if a higher-severity finding for the same sub-check exists
// (prevents double-counting in the reveal queue).
export function deductionForFinding(
  f: SubCheckFinding,
  all: SubCheckFinding[],
): number {
  const same = all.filter(x => x.subCheckId === f.subCheckId);
  const worst = same.reduce((a, b) =>
    SEVERITY_ORDER[a.severity] >= SEVERITY_ORDER[b.severity] ? a : b,
  );
  if (worst.title !== f.title) return 0;
  return Math.round(
    (SUB_CHECK_MAX[f.subCheckId] ?? 0) * SEVERITY_MULTIPLIER[f.severity] * 10,
  ) / 10;
}
