from __future__ import annotations
import asyncio
from io import BytesIO
from datetime import datetime, timedelta
from typing import AsyncGenerator, Dict, List, Optional


from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession


from ...database import get_db
from ...models.scan import Scan
from ...models.finding import Finding
from ...schemas.scan import ScanCreateRequest, ScanOut, ScanSummary, StatsOut
from ...services.orchestrator import run_scan
from ...services.report_service import generate_pdf


router = APIRouter(prefix="/scans", tags=["scans"])



# ── Extension import schemas ──────────────────────────────────────────────────


class _VulnIn(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    category: str
    evidence: Optional[str] = None
    location: Optional[str] = None
    remediation: Optional[str] = None
    cveIds: Optional[List[str]] = None
    cvssScore: Optional[float] = None
    detectedAt: Optional[int] = None   # ms epoch
    detectedBy: str = "rule"
    confidence: Optional[float] = None  # 0.0–1.0



class _ScanImport(BaseModel):
    url: str
    domain: str
    vulnerabilities: List[_VulnIn] = []
    securityScore: Optional[float] = None
    grade: Optional[str] = None
    scannedAt: Optional[int] = None     # ms epoch
    scanDurationMs: Optional[int] = None
    counts: Optional[Dict[str, int]] = None
    status: Optional[str] = "complete"



def _conf_str(c: Optional[float]) -> str:
    if c is None or c >= 0.85:
        return "CONFIRMED"
    if c >= 0.65:
        return "PROBABLE"
    if c >= 0.40:
        return "POSSIBLE"
    return "INFORMATIONAL"



@router.post("/", response_model=ScanSummary, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    body: ScanCreateRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    from urllib.parse import urlparse
    domain = urlparse(body.url).hostname or ""
    scan = Scan(url=body.url, domain=domain, status="pending")
    db.add(scan)
    await db.commit()
    await db.refresh(scan)


    background_tasks.add_task(_run_scan_task, scan.id, body.url, body.auth_token)
    return scan



async def _run_scan_task(scan_id: str, url: str, auth_token: Optional[str]):
    from ...database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan:
            return
        scan.status = "running"
        await db.commit()
        try:
            result = await run_scan(url, auth_token)
            scan.status = "complete"
            scan.completed_at = datetime.utcnow()
            scan.duration_ms = result["duration_ms"]
            scan.security_score = result["security_score"]
            scan.grade = result["grade"]
            scan.headers_raw = result.get("headers_raw")
            scan.ssl_raw = result.get("ssl_raw")
            scan.cookies_raw = result.get("cookies_raw")
            counts = result.get("counts", {})
            scan.counts_critical = counts.get("critical", 0)
            scan.counts_high = counts.get("high", 0)
            scan.counts_medium = counts.get("medium", 0)
            scan.counts_low = counts.get("low", 0)
            scan.counts_info = counts.get("info", 0)
            await db.commit()


            for fc in result.get("findings", []):
                f = Finding(
                    scan_id=scan_id,
                    vuln_id=fc.vuln_id,
                    title=fc.title,
                    description=fc.description,
                    severity=fc.severity.value,
                    confidence=fc.confidence.value,
                    category=fc.category,
                    evidence=fc.evidence,
                    location=fc.location,
                    remediation=fc.remediation,
                    cve_ids=fc.cve_ids or [],
                    cvss_score=fc.cvss_score,
                    detected_by=fc.detected_by,
                )
                db.add(f)
            await db.commit()


        except Exception as exc:
            scan.status = "failed"
            scan.error = str(exc)
            await db.commit()



@router.post("/import/", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def import_scan(body: _ScanImport, db: AsyncSession = Depends(get_db)):
    scanned_dt = (
        datetime.utcfromtimestamp(body.scannedAt / 1000)
        if body.scannedAt else datetime.utcnow()
    )
    counts = body.counts or {}
    scan = Scan(
        url=body.url,
        domain=body.domain,
        status=body.status or "complete",
        created_at=scanned_dt,
        completed_at=scanned_dt,
        duration_ms=body.scanDurationMs,
        security_score=body.securityScore,
        grade=body.grade,
        counts_critical=counts.get("critical", 0),
        counts_high=counts.get("high", 0),
        counts_medium=counts.get("medium", 0),
        counts_low=counts.get("low", 0),
        counts_info=counts.get("info", 0),
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)


    for v in body.vulnerabilities:
        det_dt = (
            datetime.utcfromtimestamp(v.detectedAt / 1000)
            if v.detectedAt else datetime.utcnow()
        )
        f = Finding(
            scan_id=scan.id,
            vuln_id=v.id,
            title=v.title,
            description=v.description,
            severity=v.severity.upper(),
            confidence=_conf_str(v.confidence),
            category=v.category,
            evidence=v.evidence,
            location=v.location,
            remediation=v.remediation,
            cve_ids=v.cveIds or [],
            cvss_score=v.cvssScore,
            detected_by=v.detectedBy,
            detected_at=det_dt,
        )
        db.add(f)
    await db.commit()


    result = await db.execute(
        select(Scan).where(Scan.id == scan.id).options(selectinload(Scan.findings))
    )
    return result.scalar_one()



@router.get("/", response_model=List[ScanSummary])
async def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Scan).order_by(Scan.created_at.desc()).offset(skip).limit(limit)
    )
    return result.scalars().all()



@router.get("/stats", response_model=StatsOut)
async def get_stats(db: AsyncSession = Depends(get_db)):
    total = (await db.execute(select(func.count(Scan.id)))).scalar_one()
    cutoff = datetime.utcnow() - timedelta(days=7)
    last7 = (await db.execute(
        select(func.count(Scan.id)).where(Scan.created_at >= cutoff)
    )).scalar_one()
    avg_score = (await db.execute(
        select(func.avg(Scan.security_score)).where(Scan.status == "complete")
    )).scalar_one()
    critical_open = (await db.execute(
        select(func.count(Finding.id)).where(
            Finding.severity == "CRITICAL", Finding.is_remediated == False
        )
    )).scalar_one()
    high_open = (await db.execute(
        select(func.count(Finding.id)).where(
            Finding.severity == "HIGH", Finding.is_remediated == False
        )
    )).scalar_one()


    cat_rows = (await db.execute(
        select(Finding.category, func.count(Finding.id).label("n"))
        .group_by(Finding.category)
        .order_by(func.count(Finding.id).desc())
        .limit(10)
    )).all()
    top_categories = [{"category": r[0], "count": r[1]} for r in cat_rows]


    return StatsOut(
        total_scans=total,
        scans_last_7d=last7,
        avg_score=round(avg_score, 1) if avg_score else None,
        critical_open=critical_open,
        high_open=high_open,
        top_categories=top_categories,
    )



@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Scan)
        .where(Scan.id == scan_id)
        .options(selectinload(Scan.findings))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan



@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    await db.delete(scan)
    await db.commit()



@router.get("/{scan_id}/report/pdf")
async def download_pdf(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")


    result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = list(result.scalars().all())


    # FIXED: generate_pdf returns bytes, but StreamingResponse needs an iterable.
    # Wrap the bytes in BytesIO so it can be iterated over.
    pdf_bytes = generate_pdf(scan, findings)
    if pdf_bytes is None or len(pdf_bytes) == 0:
        raise HTTPException(status_code=500, detail="Failed to generate PDF report")

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}.pdf"'}
    )