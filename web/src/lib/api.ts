import type { Scan, ScanSummary, Finding, Stats } from "@/types/api";

const BACKEND =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") ||
  "http://localhost:8000";

function getBase(): string {
  if (typeof window !== "undefined") {
    const stored = localStorage.getItem("cyberintel_backend_url");
    if (stored) return `${stored.replace(/\/$/, "")}/api/v1`;
  }
  return `${BACKEND}/api/v1`;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${getBase()}${path}`, {
    headers: { "Content-Type": "application/json", ...init?.headers },
    ...init,
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(err || `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  // Scans
  listScans: (skip = 0, limit = 50) =>
    req<ScanSummary[]>(`/scans/?skip=${skip}&limit=${limit}`),

  getScan: (id: string) => req<Scan>(`/scans/${id}`),

  createScan: (url: string, authToken?: string) =>
    req<ScanSummary>("/scans/", {
      method: "POST",
      body: JSON.stringify({ url, auth_token: authToken || null }),
    }),

  deleteScan: (id: string) =>
    fetch(`${getBase()}/scans/${id}`, { method: "DELETE" }),

  getStats: () => req<Stats>("/scans/stats"),

  pdfUrl: (id: string) => `${getBase()}/scans/${id}/report/pdf`,

  // Findings
  listFindings: (params: {
    scan_id?: string;
    severity?: string;
    category?: string;
    is_remediated?: boolean;
    skip?: number;
    limit?: number;
  } = {}) => {
    const qs = new URLSearchParams();
    if (params.scan_id) qs.set("scan_id", params.scan_id);
    if (params.severity) qs.set("severity", params.severity);
    if (params.category) qs.set("category", params.category);
    if (params.is_remediated !== undefined) qs.set("is_remediated", String(params.is_remediated));
    if (params.skip) qs.set("skip", String(params.skip));
    if (params.limit) qs.set("limit", String(params.limit));
    return req<Finding[]>(`/findings/?${qs}`);
  },

  markRemediated: (id: string) =>
    req<Finding>(`/findings/${id}/remediate`, { method: "PATCH" }),

  markUnremediated: (id: string) =>
    req<Finding>(`/findings/${id}/unremediate`, { method: "PATCH" }),
};
