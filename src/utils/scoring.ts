import {
  Vulnerability, Severity, SecurityGrade,
} from '../types/index';
import {
  calculateScore, deriveGrade, SubCheckFinding, SeverityLC,
} from '../scoring/engine';

// ── Adapter: Vulnerability → SubCheckFinding ─────────────
// Used anywhere we need to feed the engine from existing Vulnerability objects.
export function toSubCheckFinding(v: Vulnerability): SubCheckFinding {
  const sev = v.severity.toLowerCase() as SeverityLC;
  return {
    subCheckId: v.subCheckId ?? 'uncategorized',
    checkId:    v.checkId    ?? 'uncategorized',
    title:       v.title,
    severity:    sev,
    confidence:  v.confidence_tier ?? (v.detectedBy === 'ml' ? 'medium' : 'high'),
    observed_or_inferred: v.observed_or_inferred ?? (v.detectedBy === 'ml' ? 'inferred' : 'observed'),
    evidence:    [v.evidence],
    remediation: v.remediation,
  };
}

// ── calculateSecurityScore ────────────────────────────────
// Drop-in replacement for the old flat-deduction formula.
// Delegates to the canonical engine (per-subcheck caps, worst-per-id dedup).
export function calculateSecurityScore(vulnerabilities: Vulnerability[]): number {
  return calculateScore(vulnerabilities.map(toSubCheckFinding)).finalScore;
}

// ── scoreToGrade ──────────────────────────────────────────
// Returns SecurityGrade based on engine thresholds (A/B/C/D/E/F).
export function scoreToGrade(score: number): SecurityGrade {
  return deriveGrade(score).grade as SecurityGrade;
}

// ── countBySeverity ───────────────────────────────────────
export function countBySeverity(vulnerabilities: Vulnerability[]) {
  return {
    critical: vulnerabilities.filter(v => v.severity === Severity.CRITICAL).length,
    high:     vulnerabilities.filter(v => v.severity === Severity.HIGH).length,
    medium:   vulnerabilities.filter(v => v.severity === Severity.MEDIUM).length,
    low:      vulnerabilities.filter(v => v.severity === Severity.LOW).length,
    info:     vulnerabilities.filter(v => v.severity === Severity.INFO).length,
  };
}

// ── Colour helpers ────────────────────────────────────────
export function severityColor(severity: Severity): string {
  const colors: Record<Severity, string> = {
    [Severity.CRITICAL]: '#FF3B30',
    [Severity.HIGH]:     '#FF9500',
    [Severity.MEDIUM]:   '#FFCC00',
    [Severity.LOW]:      '#34C759',
    [Severity.INFO]:     '#5AC8FA',
  };
  return colors[severity];
}

export function gradeColor(grade: SecurityGrade): string {
  const colors: Record<SecurityGrade, string> = {
    A: '#34C759', B: '#30D158', C: '#FFCC00',
    D: '#FF9500', E: '#FF6300', F: '#FF3B30',
  };
  return colors[grade] ?? '#FF3B30';
}

// ── Sort / ID helpers ─────────────────────────────────────
export function sortBySeverity(vulnerabilities: Vulnerability[]): Vulnerability[] {
  const order: Record<Severity, number> = {
    [Severity.CRITICAL]: 0, [Severity.HIGH]: 1,
    [Severity.MEDIUM]: 2,   [Severity.LOW]: 3, [Severity.INFO]: 4,
  };
  return [...vulnerabilities].sort((a, b) => order[a.severity] - order[b.severity]);
}

export function generateVulnId(category: string, index: number): string {
  const prefix = category.replace(/\s+/g, '-').toUpperCase().slice(0, 4);
  return `${prefix}-${String(index).padStart(3, '0')}`;
}

// Re-export engine types needed by consumers
export type { SubCheckFinding } from '../scoring/engine';
export { calculateScore, deductionForFinding, deriveGrade, SUB_CHECK_MAX } from '../scoring/engine';
