from __future__ import annotations
import uuid
from typing import List, Optional
from datetime import datetime
from sqlalchemy import String, Integer, Float, Text, DateTime, JSON, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from ..database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    status: Mapped[str] = mapped_column(
        SAEnum("pending", "running", "complete", "aborted", "failed", name="scan_status"),
        default="pending",
    )
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    security_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    grade: Mapped[Optional[str]] = mapped_column(String(2), nullable=True)

    # Raw JSON snapshots from scanners
    headers_raw: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    ssl_raw: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    cookies_raw: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    dom_raw: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    ml_predictions: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    counts_critical: Mapped[int] = mapped_column(Integer, default=0)
    counts_high: Mapped[int] = mapped_column(Integer, default=0)
    counts_medium: Mapped[int] = mapped_column(Integer, default=0)
    counts_low: Mapped[int] = mapped_column(Integer, default=0)
    counts_info: Mapped[int] = mapped_column(Integer, default=0)

    findings: Mapped[List["Finding"]] = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )
