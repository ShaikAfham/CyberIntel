"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie, LineChart, Line, CartesianGrid, Legend,
} from "recharts";
import { Plus, AlertTriangle, Shield, Activity, TrendingUp, Zap, Target } from "lucide-react";
import { api } from "@/lib/api";
import type { Stats, ScanSummary, Finding } from "@/types/api";
import { ScoreRing } from "@/components/ScoreRing";
import { NewScanModal } from "@/components/NewScanModal";
import { fmtDate, fmtDateShort, GRADE_COLOR, GRADE_HEX, SEV_HEX } from "@/lib/utils";
import type { Severity } from "@/types/api";

const SEV_RANK: Record<string, number> = {
  CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0,
};

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [allScans, setAllScans] = useState<ScanSummary[]>([]);
  const [allFindings, setAllFindings] = useState<Finding[]>([]);
  const [showModal, setShowModal] = useState(false);
  const [backendDown, setBackendDown] = useState(false);

  async function load() {
    try {
      const [s, scans, findings] = await Promise.all([
        api.getStats(),
        api.listScans(0, 50),
        api.listFindings({ limit: 500 }),
      ]);
      setStats(s);
      setAllScans(scans);
      setAllFindings(findings);
      setBackendDown(false);
    } catch {
      setBackendDown(true);
    }
  }

  useEffect(() => { load(); }, []);

  const recent = allScans.slice(0, 5);

  // Most vulnerable category
  const catCounts: Record<string, number> = {};
  allFindings.forEach(f => { catCounts[f.category] = (catCounts[f.category] ?? 0) + 1; });
  const topCat = Object.entries(catCounts).sort((a, b) => b[1] - a[1])[0]?.[0] ?? "—";

  const lastScan = allScans[0];

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="text-white/40 text-sm mt-0.5">Security overview and threat intelligence</p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-2 bg-accent hover:bg-accent/80 text-white px-4 py-2 rounded-lg font-medium text-sm transition-colors"
        >
          <Plus size={16} /> New Scan
        </button>
      </div>

      {/* Backend offline banner */}
      {backendDown && (
        <div className="flex items-center gap-3 bg-critical/10 border border-critical/30 rounded-lg px-4 py-3 text-sm">
          <AlertTriangle size={16} className="text-critical flex-shrink-0" />
          <span className="text-critical/90">
            Cannot reach FastAPI backend. Start it with{" "}
            <code className="font-mono bg-black/30 px-1 rounded">python run.py</code> in the{" "}
            <code className="font-mono bg-black/30 px-1 rounded">backend/</code> directory,
            or check the URL in{" "}
            <a href="/settings" className="underline">Settings</a>.
          </span>
          <button
            onClick={load}
            className="ml-auto text-xs bg-critical/20 hover:bg-critical/30 px-3 py-1 rounded-lg text-critical flex-shrink-0"
          >
            Retry
          </button>
        </div>
      )}

      {/* KPI cards — 6 cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
        <KpiCard
          icon={<Activity size={18} />}
          label="Total Scans"
          value={stats?.total_scans ?? "—"}
        />
        <KpiCard
          icon={<TrendingUp size={18} />}
          label="Avg Score"
          value={stats?.avg_score != null ? `${Math.round(stats.avg_score)}` : "—"}
          sub="/100"
        />
        <KpiCard
          icon={<AlertTriangle size={18} className="text-critical" />}
          label="Critical Open"
          value={stats?.critical_open ?? "—"}
          danger
        />
        <KpiCard
          icon={<AlertTriangle size={18} className="text-high" />}
          label="High Open"
          value={stats?.high_open ?? "—"}
          warn
        />
        <KpiCard
          icon={<Target size={18} className="text-medium" />}
          label="Top Category"
          value={topCat}
          small
        />
        <KpiCard
          icon={<Shield size={18} className="text-accent" />}
          label="Last Score"
          value={lastScan?.security_score != null ? `${Math.round(lastScan.security_score)}` : "—"}
          sub={lastScan?.grade ? ` ${lastScan.grade}` : ""}
          accent
        />
      </div>

      {/* Charts row 1 — Gauge + Trend */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="glass p-5 flex flex-col items-center justify-center">
          <h2 className="text-xs font-semibold text-white/40 uppercase tracking-widest mb-4 self-start font-mono">
            Security Score
          </h2>
          <ScoreGauge score={stats?.avg_score ?? null} grade={null} />
        </div>

        <div className="lg:col-span-2 glass p-5">
          <h2 className="text-xs font-semibold text-white/40 uppercase tracking-widest mb-4 font-mono">
            Score Trend
          </h2>
          <TrendChart scans={allScans} />
        </div>
      </div>

      {/* Charts row 2 — Donut + Category bars */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="glass p-5">
          <h2 className="text-xs font-semibold text-white/40 uppercase tracking-widest mb-2 font-mono">
            Severity Distribution
          </h2>
          <SeverityDonut findings={allFindings} />
        </div>

        <div className="lg:col-span-2 glass p-5">
          <h2 className="text-xs font-semibold text-white/40 uppercase tracking-widest mb-4 font-mono">
            Findings by Category
          </h2>
          <CategoryBar findings={allFindings} />
        </div>
      </div>

      {/* Recent scans table */}
      <div className="glass p-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-white/60">Recent Scans</h2>
          <Link href="/scans" className="text-xs text-accent hover:underline">View all</Link>
        </div>
        {recent.length ? (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-white/30 text-xs border-b border-border">
                <th className="text-left pb-2">Domain</th>
                <th className="text-left pb-2">Status</th>
                <th className="text-left pb-2">Grade</th>
                <th className="text-left pb-2">Critical</th>
                <th className="text-left pb-2">High</th>
                <th className="text-left pb-2">Scanned</th>
              </tr>
            </thead>
            <tbody>
              {recent.map(s => (
                <tr key={s.id} className="border-b border-border/40 hover:bg-surface2/40 transition-colors">
                  <td className="py-2">
                    <Link href={`/scans/${s.id}`} className="text-accent hover:underline font-mono text-xs">
                      {s.domain}
                    </Link>
                  </td>
                  <td className="py-2"><StatusPill status={s.status} /></td>
                  <td className="py-2 font-bold font-mono text-xs" style={{ color: GRADE_HEX[s.grade ?? "F"] ?? "#ff0040" }}>
                    {s.grade ?? "—"}
                  </td>
                  <td className="py-2 text-critical font-semibold">{s.counts_critical}</td>
                  <td className="py-2 text-high font-semibold">{s.counts_high}</td>
                  <td className="py-2 text-white/40 text-xs">{fmtDate(s.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="text-white/30 text-sm">No scans yet. Start one with the button above.</p>
        )}
      </div>

      {showModal && <NewScanModal onClose={() => { setShowModal(false); load(); }} />}
    </div>
  );
}

// ─── Score Gauge (custom SVG arc) ────────────────────────────────────────────

function ScoreGauge({ score, grade }: { score: number | null; grade: string | null }) {
  const [animated, setAnimated] = useState(0);

  useEffect(() => {
    setAnimated(0);
    const t = setTimeout(() => setAnimated(score ?? 0), 120);
    return () => clearTimeout(t);
  }, [score]);

  const R = 38;
  const CIRC = 2 * Math.PI * R;
  const ARC = CIRC * 0.75;           // 270° track
  const filled = ARC * (animated / 100);
  const val = score ?? 0;
  const color = val >= 80 ? "#00ff88" : val >= 60 ? "#ffd700" : "#ff0040";
  const gradeLabel: Record<string, string> = {
    A: "Strong", B: "Good", C: "Moderate", D: "Weak", E: "Poor", F: "Critical Risk",
  };

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="160" height="160" viewBox="0 0 100 100">
        {/* Track arc */}
        <circle
          cx="50" cy="50" r={R}
          fill="none" stroke="#1a1a2e" strokeWidth="10" strokeLinecap="round"
          strokeDasharray={`${ARC} ${CIRC}`}
          transform="rotate(135 50 50)"
        />
        {/* Fill arc */}
        <circle
          cx="50" cy="50" r={R}
          fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={`${filled} ${CIRC}`}
          transform="rotate(135 50 50)"
          style={{
            transition: "stroke-dasharray 1.2s cubic-bezier(0.4,0,0.2,1)",
            filter: `drop-shadow(0 0 6px ${color})`,
          }}
        />
        <text x="50" y="46" textAnchor="middle" fill="#e0e0ff" fontSize="20" fontWeight="bold" fontFamily="monospace">
          {score != null ? Math.round(animated) : "—"}
        </text>
        <text x="50" y="59" textAnchor="middle" fill="#888899" fontSize="7.5" fontFamily="monospace" letterSpacing="1">
          AVG SCORE
        </text>
      </svg>
      {grade && (
        <p className="text-xs font-mono font-bold" style={{ color }}>
          {grade} — {gradeLabel[grade] ?? ""}
        </p>
      )}
    </div>
  );
}

// ─── Trend Line Chart ─────────────────────────────────────────────────────────

function TrendChart({ scans }: { scans: ScanSummary[] }) {
  const data = [...scans]
    .filter(s => s.security_score != null)
    .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())
    .map(s => ({
      date: fmtDateShort(s.created_at),
      score: Math.round(s.security_score!),
      domain: s.domain,
      grade: s.grade,
    }));

  if (data.length === 0) {
    return <EmptyChart label="Run a scan to see score history" />;
  }

  return (
    <ResponsiveContainer width="100%" height={200}>
      <LineChart data={data} margin={{ top: 8, right: 24, left: 0, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,245,255,0.06)" />
        <XAxis dataKey="date" tick={{ fill: "#555566", fontSize: 10, fontFamily: "monospace" }} />
        <YAxis domain={[0, 100]} tick={{ fill: "#555566", fontSize: 10, fontFamily: "monospace" }} width={28} />
        <Tooltip
          contentStyle={{ background: "#0f0f1a", border: "1px solid rgba(0,245,255,0.2)", borderRadius: 6, fontFamily: "monospace", fontSize: 12 }}
          labelStyle={{ color: "#e0e0ff", marginBottom: 4 }}
          formatter={(value: number, _: string, props: { payload?: { domain?: string; grade?: string } }) => [
            `${value}/100  (${props.payload?.grade ?? "?"})`,
            props.payload?.domain ?? "",
          ]}
        />
        <Line
          type="monotone" dataKey="score"
          stroke="#00f5ff" strokeWidth={2}
          dot={{ fill: "#00f5ff", r: 4, strokeWidth: 0 }}
          activeDot={{ r: 6, fill: "#00f5ff", strokeWidth: 2, stroke: "#0f0f1a" }}
          isAnimationActive
          animationDuration={900}
        />
      </LineChart>
    </ResponsiveContainer>
  );
}

// ─── Severity Donut ───────────────────────────────────────────────────────────

function SeverityDonut({ findings }: { findings: Finding[] }) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  findings.forEach(f => {
    if (f.severity in counts) counts[f.severity as keyof typeof counts]++;
  });

  const data = [
    { name: "Critical", value: counts.CRITICAL, color: "#ff0040" },
    { name: "High",     value: counts.HIGH,     color: "#ff6b00" },
    { name: "Medium",   value: counts.MEDIUM,   color: "#ffd700" },
    { name: "Low",      value: counts.LOW,      color: "#00aaff" },
    { name: "Info",     value: counts.INFO,     color: "#555566" },
  ].filter(d => d.value > 0);

  const total = findings.length;

  if (total === 0) {
    return <EmptyChart label="Run a scan to see severity distribution" />;
  }

  return (
    <div>
      <ResponsiveContainer width="100%" height={180}>
        <PieChart>
          <Pie
            data={data} cx="50%" cy="50%"
            innerRadius={50} outerRadius={78}
            dataKey="value"
            animationBegin={0} animationDuration={800}
          >
            {data.map((entry, i) => (
              <Cell
                key={i} fill={entry.color}
                style={{ filter: `drop-shadow(0 0 4px ${entry.color}66)` }}
              />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{ background: "#0f0f1a", border: "1px solid rgba(0,245,255,0.2)", borderRadius: 6, fontFamily: "monospace", fontSize: 11 }}
            formatter={(value: number) => [`${value}  (${((value / total) * 100).toFixed(1)}%)`, ""]}
          />
          <Legend
            formatter={(value) => <span style={{ color: "#888899", fontSize: 10, fontFamily: "monospace" }}>{value}</span>}
          />
        </PieChart>
      </ResponsiveContainer>
      <p className="text-center text-xs text-white/30 font-mono mt-1">{total} total findings</p>
    </div>
  );
}

// ─── Category Bar Chart ───────────────────────────────────────────────────────

function CategoryBar({ findings }: { findings: Finding[] }) {
  const groups: Record<string, { count: number; dominant: string }> = {};
  findings.forEach(f => {
    if (!groups[f.category]) groups[f.category] = { count: 0, dominant: "INFO" };
    groups[f.category].count++;
    if ((SEV_RANK[f.severity] ?? 0) > (SEV_RANK[groups[f.category].dominant] ?? 0)) {
      groups[f.category].dominant = f.severity;
    }
  });

  const data = Object.entries(groups)
    .map(([cat, { count, dominant }]) => ({
      category: cat,
      count,
      fill: SEV_HEX[dominant as Severity] ?? "#555566",
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 12);

  if (data.length === 0) {
    return <EmptyChart label="No findings data yet" />;
  }

  return (
    <ResponsiveContainer width="100%" height={Math.max(180, data.length * 26)}>
      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 36, top: 0, bottom: 0 }}>
        <XAxis type="number" tick={{ fill: "#555566", fontSize: 10, fontFamily: "monospace" }} />
        <YAxis
          dataKey="category" type="category"
          tick={{ fill: "#888899", fontSize: 10, fontFamily: "monospace" }}
          width={82}
        />
        <Tooltip
          contentStyle={{ background: "#0f0f1a", border: "1px solid rgba(0,245,255,0.2)", borderRadius: 6, fontFamily: "monospace", fontSize: 11 }}
          cursor={{ fill: "rgba(0,245,255,0.04)" }}
          formatter={(v: number) => [v, "findings"]}
        />
        <Bar dataKey="count" radius={[0, 4, 4, 0]} label={{ position: "right", fill: "#555566", fontSize: 9, fontFamily: "monospace" }}>
          {data.map((entry, i) => (
            <Cell key={i} fill={entry.fill} style={{ filter: `drop-shadow(0 0 3px ${entry.fill}55)` }} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function EmptyChart({ label = "No data yet" }: { label?: string }) {
  return (
    <div className="h-48 flex items-center justify-center text-white/20 text-xs font-mono">
      {label}
    </div>
  );
}

function KpiCard({
  icon, label, value, sub = "", danger = false, warn = false, accent = false, small = false,
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  sub?: string;
  danger?: boolean;
  warn?: boolean;
  accent?: boolean;
  small?: boolean;
}) {
  const iconBg = danger ? "bg-critical/10" : warn ? "bg-high/10" : accent ? "bg-accent/10" : "bg-surface2";
  const glowBorder = danger ? "hover:border-critical/40" : warn ? "hover:border-high/40" : "hover:border-accent/40";

  return (
    <div className={`glass p-4 flex items-center gap-3 ${glowBorder} transition-colors`}>
      <div className={`p-2 rounded-lg flex-shrink-0 ${iconBg}`}>{icon}</div>
      <div className="min-w-0">
        <p className="text-xs text-white/40 font-mono">{label}</p>
        <p className={`font-bold font-mono leading-tight ${small ? "text-sm truncate" : "text-lg"}`}>
          {value}<span className="text-white/40 text-xs">{sub}</span>
        </p>
      </div>
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
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
