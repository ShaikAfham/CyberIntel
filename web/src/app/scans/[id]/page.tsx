"use client";
import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie,
} from "recharts";
import { Download, RefreshCw, ChevronDown, ChevronUp, ArrowLeft } from "lucide-react";
import { api } from "@/lib/api";
import type { Scan, Finding } from "@/types/api";
import { ScoreRing } from "@/components/ScoreRing";
import { SeverityBadge } from "@/components/SeverityBadge";
import { fmtDate, fmtMs, GRADE_HEX, SEV_HEX } from "@/lib/utils";
import type { Severity } from "@/types/api";

const SEV_RANK: Record<string, number> = {
  CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0,
};
const SEV_WEIGHT: Record<string, number> = {
  CRITICAL: 10, HIGH: 6, MEDIUM: 3, LOW: 1, INFO: 0,
};

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterSev, setFilterSev] = useState<string>("ALL");
  const [downloading, setDownloading] = useState(false);

  const load = useCallback(async () => {
    try {
      setError(null);
      setScan(await api.getScan(id));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load scan");
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    load();
    const iv = setInterval(() => {
      if (scan?.status === "running" || scan?.status === "pending") load();
    }, 3000);
    return () => clearInterval(iv);
  }, [load, scan?.status]);

  async function toggleRemediated(f: Finding) {
    if (f.is_remediated) await api.markUnremediated(f.id);
    else await api.markRemediated(f.id);
    load();
  }

  async function handleDownload() {
    if (!scan) return;
    setDownloading(true);
    try {
      const base = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const res = await fetch(`${base}/api/v1/scans/${scan.id}/report/pdf`);
      if (!res.ok) throw new Error(`Server error ${res.status}`);
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `scan_${scan.id}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (e) {
      alert(`PDF download failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setDownloading(false);
    }
  }

  if (loading) return <LoadingState />;
  if (error) return (
    <div className="p-6 space-y-3">
      <Link href="/scans" className="flex items-center gap-1 text-white/40 hover:text-white text-sm">
        <ArrowLeft size={14} /> All Scans
      </Link>
      <div className="glass p-6 text-critical text-sm font-mono">Error: {error}</div>
    </div>
  );
  if (!scan) return <div className="p-6 text-white/40">Scan not found.</div>;

  const findings = scan.findings ?? [];
  const displayed = filterSev === "ALL"
    ? findings
    : findings.filter(f => f.severity === filterSev);

  const gradeHex = GRADE_HEX[scan.grade ?? "F"] ?? "#ff0040";

  // Severity counts for mini donut
  const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  findings.forEach(f => {
    if (f.severity in sevCounts) sevCounts[f.severity as keyof typeof sevCounts]++;
  });
  const donutData = [
    { name: "Critical", value: sevCounts.CRITICAL, color: "#ff0040" },
    { name: "High",     value: sevCounts.HIGH,     color: "#ff6b00" },
    { name: "Medium",   value: sevCounts.MEDIUM,   color: "#ffd700" },
    { name: "Low",      value: sevCounts.LOW,       color: "#00aaff" },
    { name: "Info",     value: sevCounts.INFO,      color: "#555566" },
  ].filter(d => d.value > 0);

  // Group findings by category for deduction chart + accordion
  const groups: Record<string, Finding[]> = {};
  findings.forEach(f => {
    if (!groups[f.category]) groups[f.category] = [];
    groups[f.category].push(f);
  });

  // Deduction score per category (weighted by severity)
  const deductionData = Object.entries(groups)
    .map(([cat, flist]) => {
      const score = flist.reduce((acc, f) => acc + (SEV_WEIGHT[f.severity] ?? 0), 0);
      const dominant = flist.reduce((worst, f) =>
        (SEV_RANK[f.severity] ?? 0) > (SEV_RANK[worst] ?? 0) ? f.severity : worst, "INFO");
      return { category: cat, score, color: SEV_HEX[dominant as Severity] ?? "#555566" };
    })
    .filter(d => d.score > 0)
    .sort((a, b) => b.score - a.score);

  return (
    <div className="p-6 space-y-6">
      {/* Breadcrumb */}
      <Link href="/scans" className="flex items-center gap-1 text-white/40 hover:text-white text-sm">
        <ArrowLeft size={14} /> All Scans
      </Link>

      {/* Header card */}
      <div className="glass p-5 flex items-start gap-6 flex-wrap">
        {/* Score ring with neon glow */}
        <div
          className="flex-shrink-0"
          style={{ filter: `drop-shadow(0 0 12px ${gradeHex}55)` }}
        >
          <ScoreRing score={scan.security_score} grade={scan.grade} size={110} />
        </div>

        {/* Info */}
        <div className="flex-1 min-w-0 space-y-1">
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-xl font-bold truncate">{scan.domain}</h1>
            <StatusChip status={scan.status} />
            {(scan.status === "running" || scan.status === "pending") && (
              <RefreshCw size={14} className="animate-spin text-accent" />
            )}
          </div>
          <p className="text-white/40 text-xs truncate">{scan.url}</p>
          <div className="flex gap-4 text-xs text-white/40 font-mono flex-wrap">
            <span>Started: {fmtDate(scan.created_at)}</span>
            <span>Duration: {fmtMs(scan.duration_ms)}</span>
            <span>ID: <code>{scan.id.slice(0, 8)}</code></span>
          </div>
          {scan.grade && (
            <div className="flex items-center gap-2 pt-1">
              <span
                className="text-sm font-bold font-mono px-3 py-1 rounded"
                style={{
                  color: gradeHex,
                  background: `${gradeHex}18`,
                  border: `1px solid ${gradeHex}40`,
                  boxShadow: `0 0 8px ${gradeHex}30`,
                }}
              >
                Grade {scan.grade}
              </span>
              <span className="text-xs text-white/40">
                {scan.security_score != null ? `${Math.round(scan.security_score)}/100` : ""}
              </span>
            </div>
          )}
        </div>

        {/* Mini donut */}
        {donutData.length > 0 && (
          <div className="flex-shrink-0 w-24">
            <PieChart width={96} height={96}>
              <Pie
                data={donutData} cx={48} cy={48}
                innerRadius={28} outerRadius={44}
                dataKey="value"
                animationBegin={0} animationDuration={700}
              >
                {donutData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
              </Pie>
              <Tooltip
                contentStyle={{ background: "#0f0f1a", border: "1px solid rgba(0,245,255,0.2)", borderRadius: 6, fontSize: 11 }}
                formatter={(v: number) => [v, ""]}
              />
            </PieChart>
          </div>
        )}

        {/* PDF button */}
        <button
          onClick={handleDownload}
          disabled={downloading}
          className="flex items-center gap-2 bg-surface2 hover:bg-border text-white px-4 py-2 rounded-lg text-sm self-start flex-shrink-0 font-mono disabled:opacity-50"
        >
          <Download size={14} /> {downloading ? "Generating…" : "PDF Report"}
        </button>
      </div>

      {/* Severity strip */}
      <div className="grid grid-cols-5 gap-3">
        {[
          { key: "CRITICAL", label: "Critical", n: scan.counts_critical, color: "border-critical text-critical" },
          { key: "HIGH",     label: "High",     n: scan.counts_high,     color: "border-high text-high" },
          { key: "MEDIUM",   label: "Medium",   n: scan.counts_medium,   color: "border-medium text-medium" },
          { key: "LOW",      label: "Low",      n: scan.counts_low,      color: "border-low text-low" },
          { key: "INFO",     label: "Info",     n: scan.counts_info,     color: "border-info text-info" },
        ].map(({ key, label, n, color }) => (
          <button
            key={key}
            onClick={() => setFilterSev(f => f === key ? "ALL" : key)}
            className={`glass p-3 text-center rounded-xl border transition-all ${
              filterSev === key ? color + " bg-white/5" : "border-border hover:border-border/80"
            }`}
          >
            <div className={`text-2xl font-bold ${color.split(" ")[1]}`}>{n}</div>
            <div className="text-xs text-white/40 mt-0.5">{label}</div>
          </button>
        ))}
      </div>

      {/* Deduction bar chart */}
      {deductionData.length > 0 && (
        <div className="glass p-5">
          <h2 className="text-xs font-semibold text-white/40 uppercase tracking-widest mb-4 font-mono">
            Risk by Category
          </h2>
          <ResponsiveContainer width="100%" height={Math.max(140, deductionData.length * 28)}>
            <BarChart data={deductionData} layout="vertical" margin={{ left: 8, right: 44, top: 0, bottom: 0 }}>
              <XAxis type="number" tick={{ fill: "#555566", fontSize: 10, fontFamily: "monospace" }} />
              <YAxis
                dataKey="category" type="category"
                tick={{ fill: "#888899", fontSize: 10, fontFamily: "monospace" }}
                width={86}
              />
              <Tooltip
                contentStyle={{ background: "#0f0f1a", border: "1px solid rgba(0,245,255,0.2)", borderRadius: 6, fontFamily: "monospace", fontSize: 11 }}
                cursor={{ fill: "rgba(0,245,255,0.04)" }}
                formatter={(v: number) => [v, "risk score"]}
              />
              <Bar dataKey="score" radius={[0, 4, 4, 0]} label={{ position: "right", fill: "#555566", fontSize: 9 }}>
                {deductionData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} style={{ filter: `drop-shadow(0 0 3px ${entry.color}55)` }} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Findings accordion by category */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <h2 className="font-semibold">
            Findings {filterSev !== "ALL" && `— ${filterSev}`}
            <span className="text-white/40 font-normal ml-2 text-sm">({displayed.length})</span>
          </h2>
          {filterSev !== "ALL" && (
            <button onClick={() => setFilterSev("ALL")} className="text-xs text-accent hover:underline">
              Show all
            </button>
          )}
        </div>

        {displayed.length === 0 && (
          <div className="glass p-8 text-center text-white/30 text-sm">
            {scan.status === "running" ? "Scan in progress…" : "No findings for this filter."}
          </div>
        )}

        {/* Group by category */}
        <CategoryAccordion
          findings={displayed}
          onToggleRemediated={toggleRemediated}
        />
      </div>
    </div>
  );
}

// ─── Category Accordion ────────────────────────────────────────────────────────

function CategoryAccordion({
  findings,
  onToggleRemediated,
}: {
  findings: Finding[];
  onToggleRemediated: (f: Finding) => void;
}) {
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set());
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  // Group by category, preserve severity sort within each group
  const sevOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const groups: Record<string, Finding[]> = {};
  findings.forEach(f => {
    if (!groups[f.category]) groups[f.category] = [];
    groups[f.category].push(f);
  });
  // Sort groups by worst severity
  const sortedGroups = Object.entries(groups).sort(([, a], [, b]) => {
    const aWorst = Math.min(...a.map(f => sevOrder.indexOf(f.severity)));
    const bWorst = Math.min(...b.map(f => sevOrder.indexOf(f.severity)));
    return aWorst - bWorst;
  });

  function toggleGroup(cat: string) {
    setOpenGroups(prev => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  }

  if (sortedGroups.length === 0) return null;

  return (
    <div className="space-y-2">
      {sortedGroups.map(([category, catFindings]) => {
        const sorted = [...catFindings].sort(
          (a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity)
        );
        const worstSev = sorted[0].severity;
        const isOpen = openGroups.has(category);

        return (
          <div key={category} className="glass overflow-hidden">
            {/* Group header */}
            <button
              onClick={() => toggleGroup(category)}
              className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/5 transition-colors"
            >
              <SeverityBadge sev={worstSev as Severity} />
              <span className="flex-1 font-semibold font-mono text-sm text-white/80">{category}</span>
              <span className="text-xs text-white/30 font-mono">{catFindings.length} finding{catFindings.length !== 1 ? "s" : ""}</span>
              {isOpen
                ? <ChevronUp size={14} className="text-white/30" />
                : <ChevronDown size={14} className="text-white/30" />}
            </button>

            {/* Expanded findings */}
            {isOpen && (
              <div className="border-t border-border divide-y divide-border/40">
                {sorted.map(f => (
                  <FindingRow
                    key={f.id}
                    finding={f}
                    expanded={expandedFinding === f.id}
                    onToggle={() => setExpandedFinding(e => e === f.id ? null : f.id)}
                    onToggleRemediated={() => onToggleRemediated(f)}
                  />
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── Finding Row ──────────────────────────────────────────────────────────────

function FindingRow({
  finding: f,
  expanded,
  onToggle,
  onToggleRemediated,
}: {
  finding: Finding;
  expanded: boolean;
  onToggle: () => void;
  onToggleRemediated: () => void;
}) {
  return (
    <div className={`transition-all ${f.is_remediated ? "opacity-50" : ""}`}>
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/5 transition-colors"
      >
        <SeverityBadge sev={f.severity} />
        <span className="flex-1 font-medium text-sm truncate">{f.title}</span>
        <span className="text-xs text-white/30 font-mono hidden sm:block">{f.vuln_id}</span>
        {f.cvss_score != null && (
          <span className="text-xs font-mono bg-surface2 px-2 py-0.5 rounded">
            CVSS {f.cvss_score.toFixed(1)}
          </span>
        )}
        {expanded
          ? <ChevronUp size={14} className="text-white/40 flex-shrink-0" />
          : <ChevronDown size={14} className="text-white/40 flex-shrink-0" />}
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-border/40 pt-3 bg-black/10">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <Detail label="ID" value={f.vuln_id} />
            <Detail label="Confidence" value={f.confidence} />
            <Detail label="Detected by" value={f.detected_by} />
            <Detail label="Location" value={f.location ?? "—"} truncate />
          </div>

          {f.description && (
            <div>
              <p className="text-xs text-white/40 mb-1 font-mono">Description</p>
              <p className="text-sm text-white/80">{f.description}</p>
            </div>
          )}

          {f.evidence && (
            <div>
              <p className="text-xs text-white/40 mb-1 font-mono">Evidence</p>
              <pre className="text-xs bg-black/40 rounded p-3 font-mono text-white/70 overflow-x-auto whitespace-pre-wrap break-all border border-border/40">
                {f.evidence}
              </pre>
            </div>
          )}

          {f.remediation && (
            <div>
              <p className="text-xs text-white/40 mb-1 font-mono">Remediation</p>
              <p className="text-sm text-low/90">{f.remediation}</p>
            </div>
          )}

          {f.cve_ids && f.cve_ids.length > 0 && (
            <div className="flex gap-2 flex-wrap">
              {f.cve_ids.map(c => (
                <span key={c} className="text-xs bg-surface2 px-2 py-0.5 rounded font-mono text-white/50">
                  {c}
                </span>
              ))}
            </div>
          )}

          <button
            onClick={onToggleRemediated}
            className={`text-xs px-3 py-1.5 rounded-lg border transition-colors font-mono ${
              f.is_remediated
                ? "border-border text-white/40 hover:border-critical hover:text-critical"
                : "border-low/40 text-low hover:bg-low/10"
            }`}
          >
            {f.is_remediated ? "Mark as Open" : "✓ Mark as Remediated"}
          </button>
        </div>
      )}
    </div>
  );
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function Detail({ label, value, truncate }: { label: string; value: string; truncate?: boolean }) {
  return (
    <div>
      <p className="text-white/30 mb-0.5 font-mono">{label}</p>
      <p className={`text-white/80 font-mono text-xs ${truncate ? "truncate" : ""}`}>{value}</p>
    </div>
  );
}

function StatusChip({ status }: { status: string }) {
  const map: Record<string, string> = {
    pending: "bg-white/10 text-white/40",
    running: "bg-accent/10 text-accent",
    complete: "bg-low/10 text-low",
    aborted: "bg-medium/10 text-medium",
    failed: "bg-critical/10 text-critical",
  };
  return (
    <span className={`text-xs px-2 py-0.5 rounded font-medium ${map[status] ?? "bg-white/10 text-white/40"}`}>
      {status}
    </span>
  );
}

function LoadingState() {
  return (
    <div className="p-6 space-y-4">
      {[1, 2, 3].map(i => (
        <div key={i} className="glass p-4 animate-pulse">
          <div className="h-4 bg-white/10 rounded w-1/3" />
          <div className="h-3 bg-white/5 rounded w-2/3 mt-2" />
        </div>
      ))}
    </div>
  );
}
