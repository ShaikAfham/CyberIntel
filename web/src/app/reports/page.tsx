"use client";
import { useEffect, useState } from "react";
import { Download, FileText } from "lucide-react";
import { api } from "@/lib/api";
import type { ScanSummary } from "@/types/api";
import { ScoreRing } from "@/components/ScoreRing";
import { fmtDate } from "@/lib/utils";

export default function ReportsPage() {
  const [scans, setScans] = useState<ScanSummary[]>([]);

  useEffect(() => {
    api.listScans().then(setScans).catch(() => {});
  }, []);

  const completed = scans.filter(s => s.status === "complete");

  return (
    <div className="p-6 space-y-5">
      <div>
        <h1 className="text-2xl font-bold">Reports</h1>
        <p className="text-white/40 text-sm mt-0.5">Download PDF security reports for completed scans</p>
      </div>

      {completed.length === 0 && (
        <div className="glass p-12 text-center text-white/30">
          No completed scans yet. Run a scan to generate a report.
        </div>
      )}

      <div className="space-y-3">
        {completed.map(s => (
          <div key={s.id} className="glass p-4 flex items-center gap-4">
            <div className="p-3 bg-accent/10 rounded-xl">
              <FileText size={24} className="text-accent" />
            </div>
            <ScoreRing score={s.security_score} grade={s.grade} size={56} />
            <div className="flex-1 min-w-0">
              <p className="font-medium truncate">{s.domain}</p>
              <p className="text-xs text-white/30 truncate">{s.url}</p>
              <div className="flex gap-3 mt-1 text-xs text-white/40">
                <span className="text-critical">{s.counts_critical} Critical</span>
                <span className="text-high">{s.counts_high} High</span>
                <span>{fmtDate(s.created_at)}</span>
              </div>
            </div>
            <a
              href={api.pdfUrl(s.id)}
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-2 bg-accent hover:bg-accent/80 text-white px-4 py-2 rounded-lg text-sm font-medium"
            >
              <Download size={14} /> PDF
            </a>
          </div>
        ))}
      </div>
    </div>
  );
}
