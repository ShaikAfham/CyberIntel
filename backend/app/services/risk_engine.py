from __future__ import annotations
from ..scanners.base import FindingCandidate, Severity, Confidence

# Penalty points per finding (severity × confidence multiplier)
SEVERITY_PENALTY = {
    Severity.CRITICAL: 30,
    Severity.HIGH:     15,
    Severity.MEDIUM:    8,
    Severity.LOW:       3,
    Severity.INFO:      0,
}

CONFIDENCE_MULTIPLIER = {
    Confidence.CONFIRMED:      1.0,
    Confidence.PROBABLE:       0.8,
    Confidence.POSSIBLE:       0.5,
    Confidence.INFORMATIONAL:  0.2,
    Confidence.BLOCKED:        0.3,
}


def compute_score(findings: list[FindingCandidate]) -> tuple[float, str]:
    """Return (score 0–100, grade A–F)."""
    total_penalty = 0.0
    for f in findings:
        penalty = SEVERITY_PENALTY[f.severity] * CONFIDENCE_MULTIPLIER[f.confidence]
        total_penalty += penalty

    score = max(0.0, 100.0 - total_penalty)
    grade = score_to_grade(score)
    return round(score, 1), grade


def score_to_grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def build_counts(findings: list[FindingCandidate]) -> dict[str, int]:
    counts = {s.value.lower(): 0 for s in Severity}
    for f in findings:
        counts[f.severity.value.lower()] += 1
    return counts
