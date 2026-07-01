"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { SeverityBadge } from "@/components/SeverityBadge";
import { api } from "@/lib/api";
import type { Finding, Severity } from "@/types/api";
import { fmtDate } from "@/lib/utils";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const PAGE_SIZE = 50;

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [sev, setSev] = useState<string>("");
  const [remFilter, setRemFilter] = useState<string>("");
  const [skip, setSkip] = useState(0);

  async function load(s = sev, r = remFilter, sk = skip) {
    const params: Parameters<typeof api.listFindings>[0] = { limit: PAGE_SIZE, skip: sk };
    if (s) params.severity = s;
    if (r !== "") params.is_remediated = r === "true";
    try { setFindings(await api.listFindings(params)); } catch {}
  }

  useEffect(() => { load(); }, []); // eslint-disable-line

  function applyFilters(newSev = sev, newRem = remFilter) {
    setSev(newSev);
    setRemFilter(newRem);
    setSkip(0);
    load(newSev, newRem, 0);
  }

  async function toggleRemediated(f: Finding) {
    if (f.is_remediated) await api.markUnremediated(f.id);
    else await api.markRemediated(f.id);
    load();
  }

  return (
    <div className="p-6 space-y-5">
      <div>
        <h1 className="text-2xl font-bold">Findings</h1>
        <p className="text-white/40 text-sm mt-0.5">All vulnerabilities across all scans</p>
      </div>

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <select
          value={sev}
          onChange={e => applyFilters(e.target.value, remFilter)}
          className="bg-surface2 border border-border rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-accent"
        >
          <option value="">All Severities</option>
          {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select
          value={remFilter}
          onChange={e => applyFilters(sev, e.target.value)}
          className="bg-surface2 border border-border rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-accent"
        >
          <option value="">All Status</option>
          <option value="false">Open</option>
          <option value="true">Remediated</option>
        </select>
        {(sev || remFilter) && (
          <button
            onClick={() => applyFilters("", "")}
            className="text-xs text-accent hover:underline px-2"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Table */}
      <div className="glass overflow-hidden">
        <table className="w-full text-sm">
          <thead className="border-b border-border">
            <tr className="text-white/30 text-xs">
              <th className="text-left px-4 py-3">Severity</th>
              <th className="text-left px-4 py-3">Title</th>
              <th className="text-left px-4 py-3">Category</th>
              <th className="text-left px-4 py-3">Confidence</th>
              <th className="text-left px-4 py-3">CVSS</th>
              <th className="text-left px-4 py-3">Detected</th>
              <th className="text-left px-4 py-3">Status</th>
            </tr>
          </thead>
          <tbody>
            {findings.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-12 text-center text-white/30">
                  No findings match the current filters.
                </td>
              </tr>
            )}
            {findings.map(f => (
              <tr
                key={f.id}
                className={`border-b border-border/40 hover:bg-surface2/40 transition-colors ${f.is_remediated ? "opacity-40" : ""}`}
              >
                <td className="px-4 py-3"><SeverityBadge sev={f.severity} /></td>
                <td className="px-4 py-3 max-w-xs">
                  <p className="truncate font-medium">{f.title}</p>
                  <p className="text-xs text-white/30 font-mono truncate">{f.vuln_id}</p>
                </td>
                <td className="px-4 py-3 text-white/50 text-xs">{f.category}</td>
                <td className="px-4 py-3 text-white/50 text-xs">{f.confidence}</td>
                <td className="px-4 py-3 text-xs font-mono">
                  {f.cvss_score != null ? f.cvss_score.toFixed(1) : "—"}
                </td>
                <td className="px-4 py-3 text-white/40 text-xs">{fmtDate(f.detected_at)}</td>
                <td className="px-4 py-3">
                  <button
                    onClick={() => toggleRemediated(f)}
                    className={`text-xs px-2 py-0.5 rounded border transition-colors ${
                      f.is_remediated
                        ? "border-border text-white/30 hover:border-critical hover:text-critical"
                        : "border-low/40 text-low hover:bg-low/10"
                    }`}
                  >
                    {f.is_remediated ? "Reopen" : "Remediated"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex gap-3 justify-end">
        <button
          disabled={skip === 0}
          onClick={() => { const s = Math.max(0, skip - PAGE_SIZE); setSkip(s); load(sev, remFilter, s); }}
          className="text-xs px-3 py-1.5 bg-surface2 hover:bg-border rounded-lg disabled:opacity-30"
        >
          ← Prev
        </button>
        <button
          disabled={findings.length < PAGE_SIZE}
          onClick={() => { const s = skip + PAGE_SIZE; setSkip(s); load(sev, remFilter, s); }}
          className="text-xs px-3 py-1.5 bg-surface2 hover:bg-border rounded-lg disabled:opacity-30"
        >
          Next →
        </button>
      </div>
    </div>
  );
}
