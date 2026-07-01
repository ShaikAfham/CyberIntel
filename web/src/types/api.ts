export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type Confidence = "CONFIRMED" | "PROBABLE" | "POSSIBLE" | "INFORMATIONAL" | "BLOCKED";
export type ScanStatus = "pending" | "running" | "complete" | "aborted" | "failed";

export interface Finding {
  id: string;
  vuln_id: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  evidence: string | null;
  location: string | null;
  remediation: string | null;
  cve_ids: string[] | null;
  cvss_score: number | null;
  detected_by: string;
  detected_at: string;
  is_remediated: boolean;
}

export interface ScanSummary {
  id: string;
  url: string;
  domain: string;
  created_at: string;
  status: ScanStatus;
  security_score: number | null;
  grade: string | null;
  counts_critical: number;
  counts_high: number;
  counts_medium: number;
  counts_low: number;
  counts_info: number;
}

export interface Scan extends ScanSummary {
  completed_at: string | null;
  duration_ms: number | null;
  error: string | null;
  findings: Finding[];
  ml_predictions: Record<string, unknown>[] | null;
}

export interface Stats {
  total_scans: number;
  scans_last_7d: number;
  avg_score: number | null;
  critical_open: number;
  high_open: number;
  top_categories: { category: string; count: number }[];
}
