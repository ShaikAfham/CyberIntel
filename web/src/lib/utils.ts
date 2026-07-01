import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import type { Severity } from "@/types/api";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: "text-critical",
  HIGH: "text-high",
  MEDIUM: "text-medium",
  LOW: "text-low",
  INFO: "text-info",
};

export const SEV_BG: Record<Severity, string> = {
  CRITICAL: "bg-critical/10 text-critical border-critical/30",
  HIGH: "bg-high/10 text-high border-high/30",
  MEDIUM: "bg-medium/10 text-medium border-medium/30",
  LOW: "bg-low/10 text-low border-low/30",
  INFO: "bg-info/10 text-info border-info/30",
};

export const GRADE_COLOR: Record<string, string> = {
  A: "text-low",
  B: "text-info",
  C: "text-medium",
  D: "text-high",
  E: "text-critical",
  F: "text-critical",
};

/** Hex color values for each grade — use in inline styles and SVG. */
export const GRADE_HEX: Record<string, string> = {
  A: "#00ff88",
  B: "#00f5ff",
  C: "#ffd700",
  D: "#ff6b00",
  E: "#ff4400",
  F: "#ff0040",
};

/** Hex color values for each severity — use in inline styles and SVG. */
export const SEV_HEX: Record<Severity, string> = {
  CRITICAL: "#ff0040",
  HIGH:     "#ff6b00",
  MEDIUM:   "#ffd700",
  LOW:      "#00aaff",
  INFO:     "#555566",
};

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

export function fmtDateShort(iso: string | null | undefined): string {
  if (!iso) return "";
  return new Date(iso).toLocaleDateString("en", { month: "short", day: "numeric" });
}

export function fmtMs(ms: number | null | undefined): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}
