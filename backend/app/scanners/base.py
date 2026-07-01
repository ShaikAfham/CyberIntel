from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum
import uuid


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    INFORMATIONAL = "INFORMATIONAL"
    BLOCKED = "BLOCKED"   # scanner was blocked / could not verify


@dataclass
class FindingCandidate:
    vuln_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    category: str
    evidence: str = ""
    location: str = ""
    remediation: str = ""
    cve_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    detected_by: str = "rule"
    id: str = field(default_factory=lambda: str(uuid.uuid4()))


class BaseScanner(ABC):
    """All scanners inherit from this. Each returns a list of FindingCandidate."""

    category: str = "Uncategorized"

    @abstractmethod
    async def scan(
        self,
        url: str,
        session,           # httpx.AsyncClient
        context: dict,     # shared data accumulated by orchestrator
        auth_token: Optional[str] = None,
    ) -> List[FindingCandidate]:
        ...
