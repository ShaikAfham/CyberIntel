from __future__ import annotations
import uuid
from typing import Optional
from datetime import datetime
from sqlalchemy import String, Float, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from ..database import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"))

    vuln_id: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. "HDR-001"
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)   # CRITICAL/HIGH/MEDIUM/LOW/INFO
    confidence: Mapped[str] = mapped_column(String(16), nullable=False) # CONFIRMED/PROBABLE/POSSIBLE/INFORMATIONAL/BLOCKED
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence: Mapped[str] = mapped_column(Text, nullable=True)
    location: Mapped[str] = mapped_column(String(2048), nullable=True)
    remediation: Mapped[str] = mapped_column(Text, nullable=True)
    cve_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    detected_by: Mapped[str] = mapped_column(String(16), default="rule")  # rule | ml
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_remediated: Mapped[bool] = mapped_column(default=False)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
