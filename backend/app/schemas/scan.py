from __future__ import annotations
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, field_validator


class ScanCreateRequest(BaseModel):
    url: str
    auth_token: Optional[str] = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class FindingOut(BaseModel):
    id: str
    vuln_id: str
    title: str
    description: str
    severity: str
    confidence: str
    category: str
    evidence: Optional[str]
    location: Optional[str]
    remediation: Optional[str]
    cve_ids: Optional[List[str]]
    cvss_score: Optional[float]
    detected_by: str
    detected_at: datetime
    is_remediated: bool

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: str
    url: str
    domain: str
    created_at: datetime
    completed_at: Optional[datetime]
    duration_ms: Optional[int]
    status: str
    error: Optional[str]
    security_score: Optional[float]
    grade: Optional[str]
    counts_critical: int
    counts_high: int
    counts_medium: int
    counts_low: int
    counts_info: int
    findings: List[FindingOut] = []
    ml_predictions: Optional[List[Dict[str, Any]]] = None

    model_config = {"from_attributes": True}


class ScanSummary(BaseModel):
    id: str
    url: str
    domain: str
    created_at: datetime
    status: str
    security_score: Optional[float]
    grade: Optional[str]
    counts_critical: int
    counts_high: int
    counts_medium: int
    counts_low: int
    counts_info: int

    model_config = {"from_attributes": True}


class StatsOut(BaseModel):
    total_scans: int
    scans_last_7d: int
    avg_score: Optional[float]
    critical_open: int
    high_open: int
    top_categories: List[Dict[str, Any]]
