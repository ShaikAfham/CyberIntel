// ============================================================
// CyberINTEL-AI — Core Types
// All interfaces, enums, and type definitions used across
// the entire extension.
// ============================================================

// ─── Severity Levels ────────────────────────────────────────
export enum Severity {
  CRITICAL = 'CRITICAL',
  HIGH     = 'HIGH',
  MEDIUM   = 'MEDIUM',
  LOW      = 'LOW',
  INFO     = 'INFO',
}

// ─── Scan Categories ────────────────────────────────────────
export enum ScanCategory {
  HEADERS          = 'Security Headers',
  SSL              = 'SSL/TLS',
  COOKIES          = 'Cookies',
  SENSITIVE_FILES  = 'Sensitive Files',
  DIRECTORY_LISTING = 'Directory Listing',
  XSS              = 'XSS Detection',
  PHISHING         = 'Phishing Detection',
  ANOMALY          = 'Behavioral Anomaly',
  SERVER_INFO      = 'Server Info Exposure',
  MIXED_CONTENT    = 'Mixed Content',
  FORMS            = 'Form Security',
  SCRIPTS          = 'Script Analysis',
  TECH_STACK       = 'Tech Stack',
  CLICKJACKING     = 'Clickjacking',
  TRACKERS         = 'Trackers',
  JWT              = 'JWT Security',
}

// ─── Scan Grade ─────────────────────────────────────────────
export type SecurityGrade = 'A' | 'B' | 'C' | 'D' | 'E' | 'F';

// ─── Individual Vulnerability Finding ───────────────────────
export interface Vulnerability {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: ScanCategory;
  evidence: string;
  location: string;
  remediation: string;
  cveIds?: string[];
  cvssScore?: number;
  detectedAt: number;
  detectedBy: 'rule' | 'ml';
  confidence?: number;
  // Trust / accuracy classification
  confidence_tier?: 'high' | 'medium' | 'low';
  observed_or_inferred?: 'observed' | 'inferred';
  // Canonical scoring engine fields
  subCheckId?: string;
  checkId?: string;
}

// ─── Security Headers Result ─────────────────────────────────
export interface HeaderAnalysis {
  present: boolean;
  value: string | null;
  secure: boolean;
  recommendation: string;
}

export interface SecurityHeaders {
  'Content-Security-Policy': HeaderAnalysis;
  'Strict-Transport-Security': HeaderAnalysis;
  'X-Frame-Options': HeaderAnalysis;
  'X-Content-Type-Options': HeaderAnalysis;
  'Referrer-Policy': HeaderAnalysis;
  'Permissions-Policy': HeaderAnalysis;
  'X-XSS-Protection': HeaderAnalysis;
}

// ─── Cookie Analysis ─────────────────────────────────────────
export interface CookieAnalysis {
  name: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'Strict' | 'Lax' | 'None' | null;
  hasPrefix: boolean;
  issues: string[];
}

// ─── SSL/TLS Analysis ────────────────────────────────────────
export interface SSLAnalysis {
  isHTTPS: boolean;
  validCert: boolean;
  expiryDate: string | null;
  issuer: string | null;
  protocol: string | null;
  grade: SecurityGrade | null;
}

// ─── ML Model Prediction ─────────────────────────────────────
export interface MLPrediction {
  modelName: 'xss' | 'phishing' | 'anomaly';
  label: string;
  confidence: number;
  isMalicious: boolean;
  features: Record<string, number>;
  inferenceTimeMs: number;
  // Extended display fields
  analysisContext?: string;  // e.g. "Analyzed 12 inputs"
  findingsSummary?: string;  // e.g. "2 potential XSS vectors found"
}

// ─── DOM Scan Result ─────────────────────────────────────────
export interface DOMScanResult {
  forms: FormAnalysis[];
  scripts: ScriptAnalysis[];
  iframes: IframeAnalysis[];
  links: LinkAnalysis[];
  inputs: InputAnalysis[];
  // Extended data from comprehensive scan
  localStorage: Record<string, string>;
  sessionStorage: Record<string, string>;
  trackers: Array<{ src: string; service: string }>;
  mixedContent: Array<{ tag: string; url: string }>;
  jwtTokens: Array<{ location: string; token: string; alg: string | null }>;
  pageTitle: string;
  faviconUrl: string | null;
  isHTTPS: boolean;
}

export interface FormAnalysis {
  action: string;
  method: string;
  hasPasswordField: boolean;
  submitsOverHTTP: boolean;
  hasAutocomplete: boolean;
  hasCsrfToken: boolean;
  selector: string;
}

export interface ScriptAnalysis {
  src: string | null;
  isInline: boolean;
  isExternal: boolean;
  domain: string | null;
  isSuspicious: boolean;
  suspicionReason: string | null;
  snippet: string | null;
  hasIntegrity?: boolean;  // undefined = inline/same-origin; true/false = external cross-origin
}

export interface IframeAnalysis {
  src: string | null;
  isSandboxed: boolean;
  isHidden: boolean;
  isThirdParty: boolean;
}

export interface LinkAnalysis {
  href: string;
  isExternal: boolean;
  isSuspicious: boolean;
}

export interface InputAnalysis {
  type: string;
  name: string;
  hasXSSPayload: boolean;
  payload: string | null;
}

// ─── Full Scan Result for a URL ───────────────────────────────
export interface ScanResult {
  id: string;
  url: string;
  domain: string;
  scannedAt: number;
  scanDurationMs: number;
  securityScore: number;
  grade: SecurityGrade;
  headers: SecurityHeaders | null;
  ssl: SSLAnalysis | null;
  cookies: CookieAnalysis[];
  dom: DOMScanResult | null;
  vulnerabilities: Vulnerability[];
  mlPredictions: MLPrediction[];
  counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  status: 'scanning' | 'complete' | 'aborted' | 'error';
  error?: string;
}

// ─── Real-time Monitoring Event ───────────────────────────────
export interface MonitorEvent {
  id: string;
  type: MonitorEventType;
  description: string;
  severity: Severity;
  timestamp: number;
  data: Record<string, unknown>;
  url: string;
}

export enum MonitorEventType {
  NEW_SCRIPT_LOADED      = 'NEW_SCRIPT_LOADED',
  INLINE_SCRIPT_INJECTED = 'INLINE_SCRIPT_INJECTED',
  DOM_MUTATION           = 'DOM_MUTATION',
  REDIRECT_DETECTED      = 'REDIRECT_DETECTED',
  NEW_IFRAME             = 'NEW_IFRAME',
  FETCH_REQUEST          = 'FETCH_REQUEST',
  XHR_REQUEST            = 'XHR_REQUEST',
  COOKIE_CHANGE          = 'COOKIE_CHANGE',
  STORAGE_WRITE          = 'STORAGE_WRITE',
  FORM_SUBMISSION        = 'FORM_SUBMISSION',
}

export type ScanState = 'idle' | 'running' | 'stopping' | 'complete' | 'failed';

// ─── ML Model Status ──────────────────────────────────────────
export interface MLModelStatus {
  xss: boolean;
  phishing: boolean;
  anomaly: boolean;
  any: boolean;
  all: boolean;
}

// ─── Message Types ────────────────────────────────────────────
export type MessageType =
  | 'SCAN_REQUEST'
  | 'SCAN_RESULT'
  | 'SCAN_PROGRESS'
  | 'MONITOR_EVENT'
  | 'GET_LATEST_SCAN'
  | 'GET_SCAN_HISTORY'
  | 'CLEAR_HISTORY'
  | 'ML_INFERENCE_REQUEST'
  | 'ML_INFERENCE_RESULT'
  | 'OFFSCREEN_ML_REQUEST'
  | 'OFFSCREEN_ML_RESULT'
  | 'ML_STATUS_REQUEST'
  | 'ML_STATUS_RESULT'
  | 'MODELS_LOADED'
  | 'MODELS_LOADING'
  | 'MODELS_ERROR'
  | 'SCAN_ABORT'
  | 'SCAN_ABORTED'
  | 'SCAN_STARTED'
  | 'SCAN_PROGRESS'
  | 'SCAN_COMPLETE'
  | 'SCAN_FAILED';

export interface ExtensionMessage {
  type: MessageType;
  tabId?: number;
  payload?: unknown;
  error?: string;
}

// ─── Storage Schema ───────────────────────────────────────────
export interface StorageSchema {
  scanHistory: ScanResult[];
  monitorEvents: MonitorEvent[];
  settings: UserSettings;
  modelsLoaded: boolean;
}

export interface UserSettings {
  enableMLScans: boolean;
  enableRealTimeMonitoring: boolean;
  enableNotifications: boolean;
  scanSensitivity: 'low' | 'medium' | 'high';
  autoScanOnVisit: boolean;
  openPageDuringScan: boolean;
  backendUrl: string | null;
  theme: 'dark' | 'light';
}

// ─── Default Settings ─────────────────────────────────────────
export const DEFAULT_SETTINGS: UserSettings = {
  enableMLScans: true,
  enableRealTimeMonitoring: true,
  enableNotifications: true,
  scanSensitivity: 'medium',
  autoScanOnVisit: false,
  openPageDuringScan: false,
  backendUrl: 'http://localhost:8000',
  theme: 'dark',
};

// ─── Scoring Weights — deducted per finding ──────────────────
export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  [Severity.CRITICAL]: 30,
  [Severity.HIGH]:     20,
  [Severity.MEDIUM]:   10,
  [Severity.LOW]:       5,
  [Severity.INFO]:      1,
};

// ─── Grade Thresholds ─────────────────────────────────────────
export const GRADE_THRESHOLDS: Record<SecurityGrade, number> = {
  A: 90,
  B: 75,
  C: 60,
  D: 45,
  E: 25,
  F: 0,
};
