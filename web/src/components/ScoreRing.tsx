"use client";
import { GRADE_COLOR } from "@/lib/utils";

const R = 42;
const CIRC = 2 * Math.PI * R;

export function ScoreRing({
  score,
  grade,
  size = 120,
}: {
  score: number | null;
  grade: string | null;
  size?: number;
}) {
  const pct = score ?? 0;
  const offset = CIRC - (pct / 100) * CIRC;
  const gradeClass = GRADE_COLOR[grade ?? "F"] ?? "text-critical";

  const strokeColor =
    pct >= 90 ? "#34C759" :
    pct >= 75 ? "#5AC8FA" :
    pct >= 60 ? "#FFB800" :
    pct >= 40 ? "#FF6B35" : "#FF2D55";

  return (
    <svg width={size} height={size} viewBox="0 0 100 100">
      <circle cx="50" cy="50" r={R} fill="none" stroke="#2C2C2E" strokeWidth="8" />
      <circle
        cx="50" cy="50" r={R}
        fill="none"
        stroke={strokeColor}
        strokeWidth="8"
        strokeLinecap="round"
        strokeDasharray={CIRC}
        strokeDashoffset={offset}
        transform="rotate(-90 50 50)"
        style={{ transition: "stroke-dashoffset 0.6s ease" }}
      />
      <text x="50" y="45" textAnchor="middle" fill="white" fontSize="18" fontWeight="bold">
        {score != null ? Math.round(score) : "—"}
      </text>
      <text x="50" y="60" textAnchor="middle" fontSize="11" className={gradeClass}
        fill={strokeColor}>
        {grade ?? "?"}
      </text>
    </svg>
  );
}
