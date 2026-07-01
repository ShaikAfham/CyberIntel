"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { Plus, Trash2, ExternalLink } from "lucide-react";
import { api } from "@/lib/api";
import type { ScanSummary } from "@/types/api";
import { NewScanModal } from "@/components/NewScanModal";
import { ScoreRing } from "@/components/ScoreRing";
import { fmtDate, GRADE_HEX } from "@/lib/utils";

const GRADE_LABEL: Record<string, string> = {
  A: "Strong", B: "Good", C: "Moderate", D: "Weak", E: "Poor", F: "Critical",
};

export default function ScansPage() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [showModal, setShowModal] = useState(false);
  const [loading, setLoading] = useState(true);

  async function load() {
    try { setScans(await api.listScans()); } catch {}
    finally { setLoading(false); }
  }

  useEffect(() => { load(); }, []);

  async function handleDelete(id: string) {
    if (!confirm("Delete this scan and all its findings?")) return;
    await api.deleteScan(id);
    load();
  }

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Scans</h1>
          <p className="text-white/40 text-sm mt-0.5">{scans.length} scans total</p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-2 bg-accent hover:bg-accent/80 text-white px-4 py-2 rounded-lg font-medium text-sm"
        >
          <Plus size={16} /> New Scan
        </button>
      </div>

      <div className="space-y-3">
        {loading && (
          <>
            {[1, 2, 3].map(i => (
              <div key={i} className="glass p-4 flex items-center gap-4 animate-pulse">
                <div className="w-16 h-16 bg-white/5 rounded-full flex-shrink-0" />
                <div className="flex-1 space-y-2">
                  <div className="h-4 bg-white/10 rounded w-1/3" />
                  <div className="h-3 bg-white/5 rounded w-2/3" />
                </div>
              </div>
            ))}
          </>
        )}
        {!loading && scans.length === 0 && (
          <div className="glass p-12 text-center text-white/30">
            No scans yet. Start your first scan above.
          </div>
        )}
        {scans.map(s => (
          <ScanCard key={s.id} scan={s} onDelete={() => handleDelete(s.id)} />
        ))}
      </div>

      {showModal && <NewScanModal onClose={() => { setShowModal(false); load(); }} />}
    </div>
  );
}

function ScanCard({ scan: s, onDelete }: { scan: ScanSummary; onDelete: () => void }) {
  const gradeHex = GRADE_HEX[s.grade ?? "F"] ?? "#ff0040";
  const score = s.security_score ?? 0;

  return (
    <div className="glass p-4 flex items-center gap-4 hover:border-accent/40 transition-colors">
      {/* Score ring */}
      <div className="flex-shrink-0">
        <ScoreRing score={s.security_score} grade={s.grade} size={64} />
      </div>

      {/* Main info */}
      <div className="flex-1 min-w-0 space-y-1">
        <div className="flex items-center gap-2 flex-wrap">
          <Link href={`/scans/${s.id}`} className="font-mono font-medium text-accent hover:underline truncate">
            {s.domain}
          </Link>
          <a href={s.url} target="_blank" rel="noreferrer" className="text-white/30 hover:text-white">
            <ExternalLink size={12} />
          </a>
          <StatusChip status={s.status} />

          {/* Grade badge */}
          {s.grade && (
            <span
              className="text-xs font-bold font-mono px-2 py-0.5 rounded"
              style={{
                color: gradeHex,
                background: `${gradeHex}18`,
                border: `1px solid ${gradeHex}40`,
                boxShadow: `0 0 6px ${gradeHex}30`,
              }}
            >
              {s.grade} — {GRADE_LABEL[s.grade] ?? s.grade}
            </span>
          )}
        </div>

        <p className="text-xs text-white/30 truncate">{s.url}</p>

        {/* Score progress bar */}
        {s.security_score != null && (
          <div className="flex items-center gap-2">
            <div className="flex-1 h-1 bg-surface2 rounded-full overflow-hidden max-w-[180px]">
              <div
                className="h-full rounded-full transition-all duration-700"
                style={{
                  width: `${score}%`,
                  background: gradeHex,
                  boxShadow: `0 0 4px ${gradeHex}66`,
                }}
              />
            </div>
            <span className="text-xs font-mono text-white/30">{Math.round(score)}/100</span>
          </div>
        )}

        {/* Finding count badges + date */}
        <div className="flex items-center gap-3 flex-wrap">
          {s.counts_critical > 0 && (
            <CountBadge count={s.counts_critical} color="#ff0040" label="Critical" />
          )}
          {s.counts_high > 0 && (
            <CountBadge count={s.counts_high} color="#ff6b00" label="High" />
          )}
          {s.counts_medium > 0 && (
            <span className="text-xs text-medium font-mono">■ {s.counts_medium} Med</span>
          )}
          <span className="text-xs text-white/30 font-mono">{fmtDate(s.created_at)}</span>
        </div>
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2 flex-shrink-0">
        <Link
          href={`/scans/${s.id}`}
          className="text-xs bg-surface2 hover:bg-border px-3 py-1.5 rounded-lg text-white/70 font-mono"
        >
          View
        </Link>
        <button
          onClick={onDelete}
          className="p-1.5 text-white/30 hover:text-critical rounded-lg hover:bg-critical/10"
        >
          <Trash2 size={14} />
        </button>
      </div>
    </div>
  );
}

function CountBadge({ count, color, label }: { count: number; color: string; label: string }) {
  return (
    <span
      className="text-xs font-bold font-mono px-1.5 py-0.5 rounded"
      style={{
        color,
        background: `${color}18`,
        border: `1px solid ${color}40`,
      }}
    >
      {count} {label}
    </span>
  );
}

function StatusChip({ status }: { status: string }) {
  const map: Record<string, string> = {
    pending: "bg-white/10 text-white/40",
    running: "bg-accent/10 text-accent animate-pulse",
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
