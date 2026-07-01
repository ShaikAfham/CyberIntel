from __future__ import annotations
import asyncio
import time
import uuid
from datetime import datetime
from urllib.parse import urlparse
from typing import AsyncGenerator, Callable

import httpx

from ..config import get_settings
from ..scanners.base import FindingCandidate
from ..scanners.headers import HeadersScanner
from ..scanners.ssl_checker import SSLScanner
from ..scanners.cookies import CookiesScanner
from ..scanners.cors_checker import CORSScanner
from ..scanners.sensitive_files import SensitiveFilesScanner
from ..scanners.injection import InjectionScanner
from ..scanners.info_disclosure import InfoDisclosureScanner
from ..scanners.access_control import AccessControlScanner
from ..scanners.mixed_content import MixedContentScanner
from .risk_engine import compute_score, build_counts

ALL_SCANNERS = [
    HeadersScanner(),
    SSLScanner(),
    CookiesScanner(),
    CORSScanner(),
    SensitiveFilesScanner(),
    InjectionScanner(),
    InfoDisclosureScanner(),
    AccessControlScanner(),
    MixedContentScanner(),
]

ProgressCallback = Callable[[str, int, str], None]  # (stage, pct, message)


async def run_scan(
    url: str,
    auth_token: str | None = None,
    on_progress: ProgressCallback | None = None,
) -> dict:
    settings = get_settings()
    scan_id = str(uuid.uuid4())
    started = time.monotonic()

    def progress(stage: str, pct: int, msg: str):
        if on_progress:
            on_progress(stage, pct, msg)

    progress("init", 0, "Initializing scan…")

    headers: dict[str, str] = {"User-Agent": "CyberINTEL-AI/1.0 Security Scanner"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}" if not auth_token.startswith("Bearer ") else auth_token

    context: dict = {}
    all_findings: list[FindingCandidate] = []

    timeout = httpx.Timeout(settings.http_request_timeout, connect=10.0)
    async with httpx.AsyncClient(headers=headers, timeout=timeout, verify=True) as session:
        total = len(ALL_SCANNERS)
        for idx, scanner in enumerate(ALL_SCANNERS):
            stage_name = scanner.category
            pct = int((idx / total) * 90)
            progress(stage_name, pct, f"Running {stage_name}…")
            try:
                results = await asyncio.wait_for(
                    scanner.scan(url, session, context, auth_token),
                    timeout=settings.http_request_timeout * 3,
                )
                all_findings.extend(results)
            except asyncio.TimeoutError:
                pass
            except Exception:
                pass

    progress("scoring", 95, "Computing risk score…")
    score, grade = compute_score(all_findings)
    counts = build_counts(all_findings)
    duration_ms = int((time.monotonic() - started) * 1000)

    progress("complete", 100, "Scan complete")

    return {
        "id": scan_id,
        "url": url,
        "domain": urlparse(url).hostname or "",
        "created_at": datetime.utcnow(),
        "completed_at": datetime.utcnow(),
        "duration_ms": duration_ms,
        "status": "complete",
        "security_score": score,
        "grade": grade,
        "findings": all_findings,
        "counts": counts,
        "headers_raw": context.get("response_headers"),
        "ssl_raw": {"protocol": context.get("ssl_proto")},
        "cookies_raw": context.get("raw_cookies"),
    }
