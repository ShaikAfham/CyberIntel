from __future__ import annotations
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...database import get_db
from ...models.finding import Finding
from ...schemas.scan import FindingOut

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("/", response_model=List[FindingOut])
async def list_findings(
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    is_remediated: Optional[bool] = None,
    skip: int = 0,
    limit: int = 200,
    db: AsyncSession = Depends(get_db),
):
    q = select(Finding)
    if scan_id:
        q = q.where(Finding.scan_id == scan_id)
    if severity:
        q = q.where(Finding.severity == severity.upper())
    if category:
        q = q.where(Finding.category == category)
    if is_remediated is not None:
        q = q.where(Finding.is_remediated == is_remediated)
    q = q.order_by(Finding.detected_at.desc()).offset(skip).limit(limit)
    result = await db.execute(q)
    return result.scalars().all()


@router.patch("/{finding_id}/remediate", response_model=FindingOut)
async def mark_remediated(finding_id: str, db: AsyncSession = Depends(get_db)):
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding.is_remediated = True
    await db.commit()
    await db.refresh(finding)
    return finding


@router.patch("/{finding_id}/unremediate", response_model=FindingOut)
async def mark_unremediated(finding_id: str, db: AsyncSession = Depends(get_db)):
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding.is_remediated = False
    await db.commit()
    await db.refresh(finding)
    return finding
